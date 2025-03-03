package getter

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
	gg "github.com/hashicorp/go-getter"

	"github.com/hashicorp/nomad/nomad/structs"
)

// httpClient is a shared HTTP client for use across all http/https Getter
// instantiations. The HTTP client is designed to be thread-safe, and using a pooled
// transport will help reduce excessive connections when clients are downloading lots
// of artifacts.
var httpClient = &http.Client{
	Transport: cleanhttp.DefaultPooledTransport(),
}

const (
	// gitSSHPrefix is the prefix for downloading via git using ssh
	gitSSHPrefix = "git@github.com:"
)

// EnvReplacer is an interface which can interpolate environment variables and
// is usually satisfied by taskenv.TaskEnv.
type EnvReplacer interface {
	ReplaceEnv(string) string
	ClientPath(string, bool) (string, bool)
}

// getClient returns a client that is suitable for Nomad downloading artifacts.
func getClient(src string, headers http.Header, mode gg.ClientMode, dst string) *gg.Client {
	return &gg.Client{
		Src:     src,
		Dst:     dst,
		Mode:    mode,
		Umask:   060000000,
		Getters: createGetters(headers),
	}
}

func createGetters(header http.Header) map[string]gg.Getter {
	httpGetter := &gg.HttpGetter{
		Netrc:  true,
		Client: httpClient,
		Header: header,
	}
	// Explicitly create fresh set of supported Getter for each Client, because
	// go-getter is not thread-safe. Use a shared HTTP client for http/https Getter,
	// with pooled transport which is thread-safe.
	//
	// If a getter type is not listed here, it is not supported (e.g. file).
	return map[string]gg.Getter{
		"git":   new(gg.GitGetter),
		"gcs":   new(gg.GCSGetter),
		"hg":    new(gg.HgGetter),
		"s3":    new(gg.S3Getter),
		"http":  httpGetter,
		"https": httpGetter,
	}
}

// getGetterUrl returns the go-getter URL to download the artifact.
func getGetterUrl(taskEnv EnvReplacer, artifact *structs.TaskArtifact) (string, error) {
	source := taskEnv.ReplaceEnv(artifact.GetterSource)

	// Handle an invalid URL when given a go-getter url such as
	// git@github.com:hashicorp/nomad.git
	gitSSH := false
	if strings.HasPrefix(source, gitSSHPrefix) {
		gitSSH = true
		source = source[len(gitSSHPrefix):]
	}

	u, err := url.Parse(source)
	if err != nil {
		return "", fmt.Errorf("failed to parse source URL %q: %v", artifact.GetterSource, err)
	}

	// Build the url
	q := u.Query()
	for k, v := range artifact.GetterOptions {
		q.Add(k, taskEnv.ReplaceEnv(v))
	}
	u.RawQuery = q.Encode()

	// Add the prefix back
	ggURL := u.String()
	if gitSSH {
		ggURL = fmt.Sprintf("%s%s", gitSSHPrefix, ggURL)
	}

	return ggURL, nil
}

func getHeaders(env EnvReplacer, m map[string]string) http.Header {
	if len(m) == 0 {
		return nil
	}

	headers := make(http.Header, len(m))
	for k, v := range m {
		headers.Set(k, env.ReplaceEnv(v))
	}
	return headers
}

// GetArtifact downloads an artifact into the specified task directory.
func GetArtifact(taskEnv EnvReplacer, artifact *structs.TaskArtifact) error {
	ggURL, err := getGetterUrl(taskEnv, artifact)
	if err != nil {
		return newGetError(artifact.GetterSource, err, false)
	}

	dest, escapes := taskEnv.ClientPath(artifact.RelativeDest, true)
	// Verify the destination is still in the task sandbox after interpolation
	if escapes {
		return newGetError(artifact.RelativeDest,
			errors.New("artifact destination path escapes the alloc directory"),
			false)
	}

	// Convert from string getter mode to go-getter const
	mode := gg.ClientModeAny
	switch artifact.GetterMode {
	case structs.GetterModeFile:
		mode = gg.ClientModeFile
	case structs.GetterModeDir:
		mode = gg.ClientModeDir
	}

	headers := getHeaders(taskEnv, artifact.GetterHeaders)
	if err := getClient(ggURL, headers, mode, dest).Get(); err != nil {
		return newGetError(ggURL, err, true)
	}

	return nil
}

// GetError wraps the underlying artifact fetching error with the URL. It
// implements the RecoverableError interface.
type GetError struct {
	URL         string
	Err         error
	recoverable bool
}

func newGetError(url string, err error, recoverable bool) *GetError {
	return &GetError{
		URL:         url,
		Err:         err,
		recoverable: recoverable,
	}
}

func (g *GetError) Error() string {
	return g.Err.Error()
}

func (g *GetError) IsRecoverable() bool {
	return g.recoverable
}
