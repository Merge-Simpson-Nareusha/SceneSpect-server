package media

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const maxImagePixels int64 = 12_000_000

var ErrInvalidImage = errors.New("invalid image")

type Store struct {
	directory string
	maxBytes  int64
}

func NewStore(directory string, maxBytes int64) (*Store, error) {
	if directory == "" || maxBytes <= 0 {
		return nil, errors.New("media storage directory and size limit are required")
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	return &Store{directory: absolute, maxBytes: maxBytes}, nil
}

func (s *Store) MaxBytes() int64 { return s.maxBytes }

// Save accepts only fully decodable JPEG and PNG files. Re-encoding strips
// embedded metadata such as EXIF location and prevents user supplied filenames
// or MIME headers from controlling the served file type.
func (s *Store) Save(input []byte) (string, error) {
	if int64(len(input)) == 0 || int64(len(input)) > s.maxBytes {
		return "", ErrInvalidImage
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(input))
	if err != nil || config.Width <= 0 || config.Height <= 0 || int64(config.Width)*int64(config.Height) > maxImagePixels {
		return "", ErrInvalidImage
	}
	if format != "jpeg" && format != "png" {
		return "", ErrInvalidImage
	}
	decoded, decodedFormat, err := image.Decode(bytes.NewReader(input))
	if err != nil || decodedFormat != format {
		return "", ErrInvalidImage
	}
	extension := ".jpg"
	if format == "png" {
		extension = ".png"
	}
	filename := uuid.NewString() + extension
	path := filepath.Join(s.directory, filename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", err
	}
	encodeErr := error(nil)
	if format == "jpeg" {
		encodeErr = jpeg.Encode(file, decoded, &jpeg.Options{Quality: 90})
	} else {
		encodeErr = png.Encode(file, decoded)
	}
	closeErr := file.Close()
	if encodeErr != nil {
		_ = os.Remove(path)
		return "", encodeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", closeErr
	}
	return "/media/" + filename, nil
}

func validFilename(value string) bool {
	if strings.HasSuffix(value, ".jpg") || strings.HasSuffix(value, ".png") {
		_, err := uuid.Parse(strings.TrimSuffix(strings.TrimSuffix(value, ".jpg"), ".png"))
		return err == nil && filepath.Base(value) == value
	}
	return false
}

func (s *Store) Path(filename string) (string, error) {
	if !validFilename(filename) {
		return "", os.ErrNotExist
	}
	return filepath.Join(s.directory, filename), nil
}
