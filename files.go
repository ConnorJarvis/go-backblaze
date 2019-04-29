package backblaze

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/readahead"

	"github.com/pquerna/ffjson/ffjson"
)

// ListFileNames lists the names of all files in a bucket, starting at a given name.
//
// See ListFileNamesWithPrefix
func (b *Bucket) ListFileNames(startFileName string, maxFileCount int) (*ListFilesResponse, error) {
	return b.ListFileNamesWithPrefix(startFileName, maxFileCount, "", "")
}

// ListFileNamesWithPrefix lists the names of all files in a bucket, starting at a given name.
//
// This call returns at most 1000 file names per transaction, but it can be called repeatedly to scan through all of the file names in a bucket.
// Each time you call, it returns a "nextFileName" that can be used as the starting point for the next call.
//
// If you set maxFileCount to more than 1000 (max 10,000) and more than 1000 are returned, the call will be billed as multiple transactions,
// as if you had made requests in a loop asking for 1000 at a time.
//
// Files returned will be limited to those with the given prefix. The empty string matches all files.
//
// If a delimiter is provided, files returned will be limited to those within the top folder, or any one subfolder.
// Folder names will also be returned. The delimiter character will be used to "break" file names into folders.
func (b *Bucket) ListFileNamesWithPrefix(startFileName string, maxFileCount int, prefix, delimiter string) (*ListFilesResponse, error) {

	if maxFileCount > 10000 || maxFileCount < 0 {
		return nil, fmt.Errorf("maxFileCount must be in range 0 to 10,000")
	}

	request := &listFilesRequest{
		BucketID:      b.ID,
		StartFileName: startFileName,
		MaxFileCount:  maxFileCount,
		Prefix:        prefix,
		Delimiter:     delimiter,
	}
	response := &ListFilesResponse{}

	if err := b.b2.apiRequest("b2_list_file_names", request, response); err != nil {
		return nil, err
	}

	return response, nil
}

// UploadFile calls UploadTypedFile with the b2/x-auto contentType
func (b *Bucket) UploadFile(name string, meta map[string]string, file io.Reader) (*File, error) {
	return b.UploadTypedFile(name, "b2/x-auto", meta, file)
}

// UploadTypedFile uploads a file to B2, returning its unique file ID.
// This method computes the hash of the file before passing it to UploadHashedFile
func (b *Bucket) UploadTypedFile(name, contentType string, meta map[string]string, file io.Reader) (*File, error) {

	// Hash the upload
	hash := sha1.New()

	var reader io.Reader
	var contentLength int64
	if r, ok := file.(io.ReadSeeker); ok {
		// If the input is seekable, just hash then seek back to the beginning
		written, err := io.Copy(hash, r)
		if err != nil {
			return nil, err
		}
		r.Seek(0, 0)
		reader = r
		contentLength = written
	} else {
		// If the input is not seekable, buffer it while hashing, and use the buffer as input
		buffer := &bytes.Buffer{}
		r := io.TeeReader(file, buffer)

		written, err := io.Copy(hash, r)
		if err != nil {
			return nil, err
		}
		reader = buffer
		contentLength = written
	}

	sha1Hash := hex.EncodeToString(hash.Sum(nil))
	f, err := b.UploadHashedTypedFile(name, contentType, meta, reader, sha1Hash, contentLength)

	// Retry after non-fatal errors
	if b2err, ok := err.(*B2Error); ok {
		if !b2err.IsFatal() && !b.b2.NoRetry {
			f, err = b.UploadHashedTypedFile(name, contentType, meta, reader, sha1Hash, contentLength)
		}
	}
	return f, err
}

// UploadHashedFile calls UploadHashedTypedFile with the b2/x-auto file type
func (b *Bucket) UploadHashedFile(
	name string, meta map[string]string, file io.Reader,
	sha1Hash string, contentLength int64) (*File, error) {

	return b.UploadHashedTypedFile(name, "b2/x-auto", meta, file, sha1Hash, contentLength)
}

// UploadHashedTypedFile Uploads a file to B2, returning its unique file ID.
//
// This method will not retry if the upload fails, as the reader may have consumed
// some bytes. If the error type is B2Error and IsFatal returns false, you may retry the
// upload and expect it to succeed eventually.
func (b *Bucket) UploadHashedTypedFile(
	name, contentType string, meta map[string]string, file io.Reader,
	sha1Hash string, contentLength int64) (*File, error) {

	auth, err := b.GetUploadAuth()
	if err != nil {
		return nil, err
	}

	if b.b2.Debug {
		fmt.Printf("         Upload: %s/%s\n", b.Name, name)
		fmt.Printf("           SHA1: %s\n", sha1Hash)
		fmt.Printf("  ContentLength: %d\n", contentLength)
		fmt.Printf("    ContentType: %s\n", contentType)
	}

	// Create authorized request
	req, err := http.NewRequest("POST", auth.UploadURL.String(), file)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", auth.AuthorizationToken)

	// Set file metadata
	req.ContentLength = contentLength
	// default content type
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Bz-File-Name", url.QueryEscape(name))
	req.Header.Set("X-Bz-Content-Sha1", sha1Hash)

	if meta != nil {
		for k, v := range meta {
			req.Header.Add("X-Bz-Info-"+url.QueryEscape(k), url.QueryEscape(v))
		}
	}

	resp, err := b.b2.httpClient.Do(req)
	if err != nil {
		auth.Valid = false
		return nil, err
	}

	// Place the UploadAuth back in the pool
	b.ReturnUploadAuth(auth)

	result := &File{}

	// We are not dealing with the b2 client auth token in this case, hence the nil auth
	if err := b.b2.parseResponse(resp, result, nil); err != nil {
		auth.Valid = false
		return nil, err
	}

	if sha1Hash != result.ContentSha1 {
		return nil, errors.New("SHA1 of uploaded file does not match local hash")
	}

	return result, nil
}

// GetFileInfo retrieves information about one file stored in B2.
func (b *Bucket) GetFileInfo(fileID string) (*File, error) {
	request := &fileRequest{
		ID: fileID,
	}
	response := &File{}

	if err := b.b2.apiRequest("b2_get_file_info", request, response); err != nil {
		return nil, err
	}

	return response, nil
}

// DownloadFileByID downloads a file from B2 using its unique ID
func (c *B2) DownloadFileByID(fileID string) (*File, io.ReadCloser, error) {
	return c.DownloadFileRangeByID(fileID, nil)
}

// DownloadFileRangeByID downloads part of a file from B2 using its unique ID and a requested byte range.
func (c *B2) DownloadFileRangeByID(fileID string, fileRange *FileRange) (*File, io.ReadCloser, error) {

	request := &fileRequest{
		ID: fileID,
	}

	if c.Debug {
		fmt.Println("---")
		fmt.Printf("  Download by ID: %s\n", fileID)
		fmt.Printf("           Range: %+v\n", fileRange)
		fmt.Printf("         Request: %+v\n", request)
	}

	requestBody, err := ffjson.Marshal(request)
	if err != nil {
		return nil, nil, err
	}

	f, body, err := c.tryDownloadFileByID(requestBody, fileRange)

	// Retry after non-fatal errors
	if b2err, ok := err.(*B2Error); ok {
		if !b2err.IsFatal() && !c.NoRetry {
			return c.tryDownloadFileByID(requestBody, fileRange)
		}
	}
	return f, body, err
}

func (c *B2) tryDownloadFileByID(requestBody []byte, fileRange *FileRange) (*File, io.ReadCloser, error) {
	req, auth, err := c.authRequest("POST", "b2_download_file_by_id", bytes.NewReader(requestBody))
	if err != nil {
		return nil, nil, err
	}

	if fileRange != nil {
		req.Header.Add("Range", fmt.Sprintf("bytes=%d-%d", fileRange.Start, fileRange.End))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	return c.downloadFile(resp, auth)
}

// FileURL returns a URL which may be used to download the latest version of a file.
// This returned URL will only work for public buckets unless the correct authorization header is provided.
func (b *Bucket) FileURL(fileName string) (string, error) {
	fileURL, _, err := b.internalFileURL(fileName)
	return fileURL, err
}

// The B2 authRequest method assumes we are making a call to the API endpoint, so here we need to check the
// authorization again and pass it to the caller so that they can generate an authorized request if needed
func (b *Bucket) internalFileURL(fileName string) (string, *authorizationState, error) {
	b.b2.mutex.Lock()
	defer b.b2.mutex.Unlock()

	if !b.b2.auth.isValid() {
		if err := b.b2.internalAuthorizeAccount(); err != nil {
			return "", nil, err
		}
	}
	return b.b2.auth.DownloadURL + "/file/" + b.Name + "/" + fileName, b.b2.auth, nil
}

// DownloadFileByName downloads one file by providing the name of the bucket and the name of the
// file.
func (b *Bucket) DownloadFileByName(fileName string) (*File, io.ReadCloser, error) {
	return b.DownloadFileRangeByName(fileName, nil)
}

// DownloadFileRangeByName downloads part of a file by providing the name of the bucket, the name of the
// file, and a requested byte range
func (b *Bucket) DownloadFileRangeByName(fileName string, fileRange *FileRange) (*File, io.ReadCloser, error) {

	if b.b2.Debug {
		fmt.Println("---")
		fmt.Printf("  Download by name: %s/%s\n", b.Name, fileName)
		fmt.Printf("             Range: %+v\n", fileRange)
	}

	f, body, err := b.tryDownloadFileByName(fileName, fileRange)

	// Retry after non-fatal errors
	if b2err, ok := err.(*B2Error); ok {
		if !b2err.IsFatal() && !b.b2.NoRetry {
			return b.tryDownloadFileByName(fileName, fileRange)
		}
	}
	return f, body, err
}

// ReadaheadFileByName attempts to load chunks of the file being downloaded ahead of time to improve transfer rates.
// File ranges are downloaded using Content-Range requests. See DownloadFileRangeByName
func (b *Bucket) ReadaheadFileByName(fileName string) (*File, io.ReadCloser, error) {
	resp, err := b.ListFileNames(fileName, 1)
	if err != nil {
		return nil, nil, err
	}
	if len(resp.Files) != 1 || resp.Files[0].Name != fileName {
		return nil, nil, fmt.Errorf("Unable to find file %s in bucket %s", fileName, b.Name)
	}

	file := &resp.Files[0].File
	r, err := b.b2.ReadaheadFile(file)
	return file, r, err
}

// ReadaheadFile attempts to load chunks of the file being downloaded ahead of time to improve transfer rates.
// This method attempts to optimise the chunk size based on the file size and a target of 15 workers
//
// File ranges are downloaded using Content-Range requests. See DownloadFileRangeByName
func (c *B2) ReadaheadFile(file *File) (io.ReadCloser, error) {
	numWorkers := 15
	chunkSize := int(file.ContentLength / int64(numWorkers*2))
	if chunkSize < 1<<20 {
		chunkSize = 1 << 20
	} else if chunkSize > 10<<20 {
		chunkSize = 10 << 20
	}
	return c.ReadaheadFileOptions(file, chunkSize, numWorkers*2, numWorkers)
}

// ReadaheadFileOptions attempts to load chunks of the file being downloaded ahead of time to improve transfer rates.
// This method extends ReadaheadFile with options to configure the chunk size, number of chunks to read ahead
// and the number of workers to use.
//
// File ranges are downloaded using Content-Range requests. See DownloadFileRangeByName
func (c *B2) ReadaheadFileOptions(file *File, chunkSize, chunkAhead, numWorkers int) (io.ReadCloser, error) {
	readerAt := &fileReaderAt{
		b2:   c,
		file: file,
	}

	reader := readahead.NewConcurrentReader(file.Name, readerAt, chunkSize, chunkAhead, numWorkers)
	return reader, nil
}

type fileReaderAt struct {
	b2   *B2
	file *File
}

func (r *fileReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	// Check range being requested is valid
	// Have we overshot?
	if off >= r.file.ContentLength {
		if r.b2.Debug {
			log.Printf("Requested offset %d is past end of file (%d)", off, r.file.ContentLength)
		}
		return 0, io.EOF
	}

	// Request range from B2
	fileRange := &FileRange{
		Start: off,
		End:   off + int64(len(p)),
	}
	if r.b2.Debug {
		log.Printf("Reading chunk of %d bytes at offset %d", len(p), off)
	}
	_, reader, err := r.b2.DownloadFileRangeByID(r.file.ID, fileRange)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	defer reader.Close()

	// Read chunk
	n, err = io.ReadFull(reader, p)
	if r.b2.Debug {
		log.Printf("Read %d bytes of %d requested at offset %d", n, len(p), off)
	}
	if err != nil {
		if r.b2.Debug {
			log.Println(err)
		}
	}
	// Handle last chunk
	if off+int64(len(p)) > r.file.ContentLength {
		if int64(n) == r.file.ContentLength-off {
			err = io.EOF
		}
	}
	return n, err
}

func (b *Bucket) tryDownloadFileByName(fileName string, fileRange *FileRange) (*File, io.ReadCloser, error) {
	// Locate the file
	fileURL, auth, err := b.internalFileURL(fileName)
	if err != nil {
		return nil, nil, err
	}

	if b.b2.Debug {
		fmt.Printf("  Download URL: %s\n", fileURL)
	}

	// Make the download request
	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Authorization", auth.AuthorizationToken)

	if fileRange != nil {
		req.Header.Add("Range", fmt.Sprintf("bytes=%d-%d", fileRange.Start, fileRange.End))
	}

	resp, err := b.b2.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}

	// Handle the response
	return b.b2.downloadFile(resp, auth)
}

func (c *B2) downloadFile(resp *http.Response, auth *authorizationState) (*File, io.ReadCloser, error) {
	success := false
	defer func() {
		if !success {
			resp.Body.Close()
		}
	}()

	if c.Debug {
		fmt.Printf("  Response status: %d\n", resp.StatusCode)
		fmt.Printf("          Headers: %+v\n", resp.Header)
	}

	switch resp.StatusCode {
	case 200:
	case 206:
	case 401:
		auth.invalidate()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}
		if err := c.parseError(body); err != nil {
			return nil, nil, err
		}
		return nil, nil, &B2Error{
			Code:    "UNAUTHORIZED",
			Message: "The account ID is wrong, the account does not have B2 enabled, or the application key is not valid",
			Status:  resp.StatusCode,
		}
	default:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}
		if err := c.parseError(body); err != nil {
			return nil, nil, err
		}

		return nil, nil, fmt.Errorf("Unrecognised status code: %d", resp.StatusCode)
	}

	name, err := url.QueryUnescape(resp.Header.Get("X-Bz-File-Name"))
	if err != nil {
		return nil, nil, err
	}

	file := &File{
		ID:          resp.Header.Get("X-Bz-File-Id"),
		Name:        name,
		ContentSha1: resp.Header.Get("X-Bz-Content-Sha1"),
		ContentType: resp.Header.Get("Content-Type"),
		FileInfo:    make(map[string]string),
	}

	// Parse Content-Length
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		return nil, nil, err
	}
	file.ContentLength = size

	// Parse Content-Range
	contentRange := resp.Header.Get("Content-Range")
	if contentRange != "" {
		var start, end, total int64
		_, err := fmt.Sscanf(contentRange, "bytes %d-%d/%d", &start, &end, &total)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to parse Content-Range header: %s", err)
		}
		if end-start+1 != file.ContentLength {
			return nil, nil, fmt.Errorf("Content-Range (%d-%d) does not match Content-Length (%d)", start, end, file.ContentLength)
		}
	}

	for k, v := range resp.Header {
		if strings.HasPrefix(k, "X-Bz-Info-") {
			key, err := url.QueryUnescape(k[len("X-Bz-Info-"):])
			if err != nil {
				key = k[len("X-Bz-Info-"):]
				log.Printf("Unable to decode key: %q", key)
			}

			value, err := url.QueryUnescape(v[0])
			if err != nil {
				value = v[0]
				log.Printf("Unable to decode value: %q", value)
			}
			file.FileInfo[key] = value
		}
	}

	success = true // Don't close the response body
	return file, resp.Body, nil
}

// ListFileVersions lists all of the versions of all of the files contained in
// one bucket, in alphabetical order by file name, and by reverse of date/time
// uploaded for versions of files with the same name.
func (b *Bucket) ListFileVersions(startFileName, startFileID string, maxFileCount int) (*ListFileVersionsResponse, error) {
	request := &listFileVersionsRequest{
		BucketID:      b.ID,
		StartFileName: startFileName,
		StartFileID:   startFileID,
		MaxFileCount:  maxFileCount,
	}
	response := &ListFileVersionsResponse{}

	if err := b.b2.apiRequest("b2_list_file_versions", request, response); err != nil {
		return nil, err
	}

	return response, nil
}

// DeleteFileVersion deletes one version of a file from B2.
//
// If the version you delete is the latest version, and there are older
// versions, then the most recent older version will become the current
// version, and be the one that you'll get when downloading by name. See the
// File Versions page for more details.
func (b *Bucket) DeleteFileVersion(fileName, fileID string) (*FileStatus, error) {
	request := &fileVersionRequest{
		Name: fileName,
		ID:   fileID,
	}
	response := &FileStatus{}

	if err := b.b2.apiRequest("b2_delete_file_version", request, response); err != nil {
		return nil, err
	}

	return response, nil
}

// HideFile hides a file so that downloading by name will not find the file,
// but previous versions of the file are still stored. See File Versions about
// what it means to hide a file.
func (b *Bucket) HideFile(fileName string) (*FileStatus, error) {
	request := &hideFileRequest{
		BucketID: b.ID,
		FileName: fileName,
	}
	response := &FileStatus{}

	if err := b.b2.apiRequest("b2_hide_file", request, response); err != nil {
		return nil, err
	}

	return response, nil
}

// LargeFile provides access to an uploadAuthPool for the LargeFile
type LargeFile struct {
	*StartLargeFileResponse
	filePath       string
	uploadAuthPool chan *UploadAuth
	partPool       chan *Part
	b2             *B2
	// State
	mutex sync.Mutex
}

// Part describes a part of a LargeFile that needs to be uploaded
type Part struct {
	number    int
	startByte int64
	endByte   int64
}

// UploadLargeFile handles the full process of a multipart upload
func (b *Bucket) UploadLargeFile(fileName string, contentType *string, fileInfo *map[string]string, filePath string, uploadThreads int) (*FinishLargeFileResponse, error) {
	// Open file to get stats for upload
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	stats, err := file.Stat()
	if err != nil {
		return nil, err
	}
	contentLength := stats.Size()
	file.Close()
	// Check that the supplied file isn't too small
	if contentLength < b.b2.AbsoluteMinimumPartSize+1 {
		return nil, errors.New("File is smaller then the minimum large_file size")
	}
	// Decide on the part size for the upload
	partSize := b.b2.RecommendedPartSize
	if contentLength-1 < int64(b.b2.RecommendedPartSize) {
		partSize = contentLength - 1
	}
	// Start the large file
	largeFileResponse, err := b.StartLargeFile(fileName, contentType, fileInfo)
	if err != nil {
		return nil, fmt.Errorf("Unable to start large file upload: %s", err)
	}
	largeFile := &LargeFile{
		StartLargeFileResponse: largeFileResponse,
		filePath:               filePath,
		partPool:               make(chan *Part, int(math.Ceil(float64(contentLength)/float64(partSize)))),
		uploadAuthPool:         make(chan *UploadAuth, b.b2.MaxIdleUploads),
		b2:                     b.b2,
	}
	// Fill the part channel
	for i := 1; i <= int(math.Ceil(float64(contentLength)/float64(partSize))); i++ {
		largeFile.partPool <- &Part{
			number:    i,
			startByte: (int64(i) - 1) * partSize,
			endByte:   int64(math.Min(float64(int64(i)*partSize), float64(contentLength))),
		}
	}

	parts := make([]string, 0)
	var wg sync.WaitGroup

	wg.Add(int(math.Ceil(float64(contentLength) / float64(partSize))))

	for i := 0; i < uploadThreads; i++ {
		go func() {
			for {
				part, ok := <-largeFile.partPool
				if !ok {
					break
				}
				resp, err := largeFile.UploadPart(part)
				if err != nil {
					fmt.Errorf("Unable to upload large file part: %s", err)
				}
				largeFile.mutex.Lock()
				parts = append(parts, resp.ContentSha1)
				largeFile.mutex.Unlock()
				wg.Done()
			}
		}()
	}
	wg.Wait()
	close(largeFile.partPool)
	finishLargeFile, err := largeFile.b2.FinishLargeFile(largeFileResponse.ID, parts)
	if err != nil {
		return nil, fmt.Errorf("Failed to finish large file: %s", err)
	}
	return finishLargeFile, nil
}

// UploadPart reterives a part from the pool and uploads it
func (l *LargeFile) UploadPart(part *Part) (*UploadPartResponse, error) {

	file, err := os.Open(l.filePath)
	if err != nil {
		return nil, err
	}
	r := io.ReadSeeker(file)
	// Hash the upload
	hash := sha1.New()

	r.Seek(part.startByte, io.SeekStart)
	lr := io.LimitReader(r, part.endByte-part.startByte)
	// If the input is seekable, just hash then seek back to the beginning
	_, err = io.Copy(hash, lr)
	if err != nil {
		return nil, err
	}
	r.Seek(part.startByte, io.SeekStart)

	sha1Hash := hex.EncodeToString(hash.Sum(nil))
	f, err := l.UploadHashedPart(sha1Hash, part.endByte-part.startByte, part)

	// Retry after non-fatal errors
	if b2err, ok := err.(*B2Error); ok {
		if !b2err.IsFatal() && !l.b2.NoRetry {
			f, err = l.UploadHashedPart(sha1Hash, part.endByte-part.startByte, part)
		}
	}
	file.Close()
	return f, err

}

// UploadHashedPart Uploads a part of a large_file to B2, returning its Sha1 value
func (l *LargeFile) UploadHashedPart(sha1Hash string, contentLength int64, part *Part) (*UploadPartResponse, error) {

	auth, err := l.GetLargeFileUploadAuth()
	if err != nil {
		return nil, err
	}

	if l.b2.Debug {
		fmt.Printf("         Upload: %s\n", l.Name)
		fmt.Printf("    Part Number: %d\n", part.number)
		fmt.Printf("           SHA1: %s\n", sha1Hash)
		fmt.Printf("  ContentLength: %d\n", contentLength)
	}
	file, err := os.Open(l.filePath)
	if err != nil {
		return nil, err
	}
	r := io.ReadSeeker(file)

	r.Seek(part.startByte, io.SeekStart)
	lr := io.LimitReader(r, part.endByte-part.startByte)
	// Create authorized request
	req, err := http.NewRequest("POST", auth.UploadURL.String(), lr)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", auth.AuthorizationToken)

	// Set file metadata
	req.ContentLength = contentLength
	// default content type
	req.Header.Set("X-Bz-Part-Number", strconv.Itoa(part.number))
	req.Header.Set("X-Bz-Content-Sha1", sha1Hash)

	resp, err := l.b2.httpClient.Do(req)
	file.Close()
	if err != nil {
		auth.Valid = false
		return nil, err
	}

	// Place the UploadAuth back in the pool
	l.ReturnLargeFileUploadAuth(auth)

	result := &UploadPartResponse{}

	// We are not dealing with the b2 client auth token in this case, hence the nil auth
	if err := l.b2.parseResponse(resp, result, nil); err != nil {
		auth.Valid = false
		return nil, err
	}

	if sha1Hash != result.ContentSha1 {
		return nil, errors.New("SHA1 of uploaded file does not match local hash")
	}

	return result, nil
}

// StartLargeFile prepares a large_file for upload returning the file ID
func (b *Bucket) StartLargeFile(fileName string, contentType *string, fileInfo *map[string]string) (*StartLargeFileResponse, error) {
	if contentType == nil {
		defaultContentType := "b2/x-auto"
		contentType = &defaultContentType
	}
	request := &startLargeFileRequest{
		BucketID:    b.ID,
		Name:        fileName,
		ContentType: *contentType,
		FileInfo:    fileInfo,
	}
	response := &StartLargeFileResponse{}

	if err := b.b2.apiRequest("b2_start_large_file", request, response); err != nil {
		return nil, err
	}

	return response, nil
}

// FinishLargeFile converts the parts uploaded from b2_get_upload_part_url into the final file
func (c *B2) FinishLargeFile(fileID string, partSha1Array []string) (*FinishLargeFileResponse, error) {
	request := &finishLargeFileRequest{
		ID:            fileID,
		PartSha1Array: partSha1Array,
	}
	response := &FinishLargeFileResponse{}

	if err := c.apiRequest("b2_finish_large_file", request, response); err != nil {
		return nil, err
	}

	return response, nil
}
