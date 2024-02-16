package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	sessionName          = "oidc-tester"
	sessionValueTokenKey = "oidc-token"

	sessionErrorMessageKey = "oidc-tester-error-message"

	storeOIDCProviderKey       = "oidc-provider"
	storeOIDCProviderConfigKey = "oidc-provider-config"
	storeOIDCProviderInfoKey   = "oidc-provider-info"

	configHandlerPath   = "/config"
	logoutHandlerPath   = "/logout"
	callbackHandlerPath = "/openid-connect/callback"

	idTokenKey = "id_token"
)

//go:embed template/*
var tplEmbed embed.FS

// in-memory store for OIDC provider config
var cfgStore = &sync.Map{}

func indexHandler(
	logger *slog.Logger,
	session sessions.Store,
	httpClient *http.Client,
	logBuffer *bytes.Buffer,
) http.HandlerFunc {
	templates := []string{
		"template/base.gohtml",
		"template/index.gohtml",
	}
	tpl := template.Must(template.New("").ParseFS(tplEmbed, templates...))
	return func(w http.ResponseWriter, r *http.Request) {
		storedOp, ok := cfgStore.Load(storeOIDCProviderKey)
		if !ok {
			http.Redirect(w, r, configHandlerPath, http.StatusFound)
			return
		}
		op, ok := storedOp.(*OIDCProvider)
		if !ok {
			http.Error(w, "index: invalid OIDCProvider", http.StatusInternalServerError)
			return
		}
		r = r.WithContext(oidc.ClientContext(r.Context(), httpClient))
		opEndpoint := op.Provider.Endpoint()
		logger.Info("index: Start")
		if _, err := session.Get(r, sessionName); err != nil {
			logger.Warn("index: Session not found, redirect to OIDC authURL",
				slog.Any("error", err),
				slog.Any("url", opEndpoint.AuthURL),
			)
			op.redirectToAuth(w, r)
			return
		}
		storedToken, ok := cfgStore.Load(sessionValueTokenKey)
		if !ok {
			logger.Warn("index: Session token not found, redirect to OIDC authURL",
				slog.Any("url", opEndpoint.AuthURL),
			)
			op.redirectToAuth(w, r)
			return
		}
		token, ok := storedToken.(*oauth2.Token)
		if !ok {
			logger.Error("index: Session token is not *oauth2.Token",
				slog.Any("url", opEndpoint.AuthURL),
			)
			http.Error(w, "index: Session token is not *oauth2.Token", http.StatusInternalServerError)
			return
		}
		if token == nil {
			logger.Error("index: Nil token, redirect to OIDC authURL",
				slog.Any("url", opEndpoint.AuthURL),
			)
			op.redirectToAuth(w, r)
		}
		logger.Info("index: Getting user information")
		oidcCtx := oidc.ClientContext(r.Context(), httpClient)
		user, err := op.Provider.UserInfo(oidcCtx, oauth2.StaticTokenSource(token))
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				logger.Error("index: Failed to get user info, redirect to OIDC authURL",
					slog.Any("error", err),
					slog.Any("url", opEndpoint.AuthURL),
				)
				op.redirectToAuth(w, r)
			}
			return
		}
		logger.Info("index: Done")
		var userInfo map[string]any
		if err = user.Claims(&userInfo); err != nil {
			logger.Error("index: Failed to parse user info claim", "error", err)
			http.Error(w, "index: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tokenJSON, _ := json.MarshalIndent(token, "", "  ")
		var providerInfoJSON string
		if storedProviderInfo, ok := cfgStore.Load(storeOIDCProviderInfoKey); ok {
			providerInfoJSON = storedProviderInfo.(string)
		}
		userInfoJSON, _ := json.MarshalIndent(userInfo, "", " ")
		err = tpl.ExecuteTemplate(w, "base.gohtml", map[string]any{
			"providerInfo": providerInfoJSON,
			"userInfoJSON": string(userInfoJSON),
			"token":        string(tokenJSON),
			"logs":         logBuffer.String(), // dump the logs
			"logoutPath":   logoutHandlerPath,
		})
		// reset after dump.
		logBuffer.Reset()
		if err != nil {
			logger.Error("index: execute template failed", slog.Any("error", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func callbackHandler(logger *slog.Logger, session sessions.Store, httpClient *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		storedOp, ok := cfgStore.Load(storeOIDCProviderKey)
		if !ok {
			http.Redirect(w, r, configHandlerPath, http.StatusFound)
			return
		}
		op, ok := storedOp.(*OIDCProvider)
		if !ok {
			http.Error(w, "index: invalid OIDCProvider", http.StatusInternalServerError)
			return
		}
		// use previously defined HTTP client which include logger.
		r = r.WithContext(oidc.ClientContext(r.Context(), httpClient))
		// TODO: check "state" value here.
		logger.Debug("callback: Callback received", slog.String("query", r.URL.RawQuery))
		token, err := op.Oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			var oauthErr *oauth2.RetrieveError
			if errors.As(err, &oauthErr) {
				op.redirectToAuth(w, r, oauth2.ApprovalForce)
				return
			}
			logger.Error("callback: Exchange authorization failed", slog.Any("error", err))
			http.Error(w, "callback: "+err.Error(), http.StatusInternalServerError)
			return
		}
		idTokenRaw, ok := token.Extra(idTokenKey).(string)
		if !ok {
			logger.Error("callback: Token does not contain id_token")
			http.Redirect(w, r, configHandlerPath, http.StatusFound)
			return
		}
		logger.Debug("callback: Verify id_token using provider certificates")
		idToken, err := op.IDTokenVerifier.Verify(r.Context(), idTokenRaw)
		if err != nil {
			logger.Error("callback: id_token could not be verified", slog.Any("error", err))
			http.Redirect(w, r, configHandlerPath, http.StatusFound)
			return
		}
		logger.Debug("callback: Verify access_token")
		if err = idToken.VerifyAccessToken(token.AccessToken); err != nil {
			logger.Error("callback: access_token could not be verified", slog.Any("error", err))
			http.Redirect(w, r, configHandlerPath, http.StatusFound)
			return
		}
		logger.Debug("callback: Authorization code exchange success")
		logger.Debug("callback: token_type", slog.String("token_type", token.TokenType))
		logger.Debug("callback: access_token", slog.String("access_token", token.AccessToken))
		logger.Debug("callback: refresh_token", slog.String("refresh_token", token.RefreshToken))
		logger.Debug("callback: id_token", slog.String("id_token", idTokenRaw))
		// this is not actual access token expiry
		// parse access token to get the actual access token expiry.
		logger.Debug("callback: expiry", slog.Int("expiry", token.Expiry.Second()))
		s, err := session.Get(r, sessionName)
		if err != nil {
			logger.Debug("callback: Reusing session failed, create a new one")
			s, err = session.New(r, sessionName)
		}
		if s == nil && err != nil {
			logger.Error("callback: Failed to setup session", "error", err)
			http.Error(w, "Failed to setup session", http.StatusInternalServerError)
			return
		}
		s.Options.MaxAge = token.Expiry.Second()
		// we save to sync.Map because cookie store have limitation on the size of the value.
		cfgStore.Store(sessionValueTokenKey, token)
		if err = session.Save(r, w, s); err != nil {
			logger.Error("callback: Failed to save session", "error", err)
			http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

type OIDCConfig struct {
	IssuerURL    string `json:"issuer_url,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`
}

func (cfg *OIDCConfig) validate() error {
	if cfg.IssuerURL == "" {
		return fmt.Errorf("issuer_url cannot be empty")
	}
	if cfg.ClientID == "" {
		return fmt.Errorf("client_id cannot be empty")
	}
	if cfg.RedirectURL == "" {
		return fmt.Errorf("redirect_url cannot be empty")
	}
	return nil
}

func (cfg *OIDCConfig) Provider(ctx context.Context, httpClient *http.Client) (*OIDCProvider, error) {
	// oidc
	oidcCtx := oidc.ClientContext(ctx, httpClient)
	oidcProvider, err := oidc.NewProvider(oidcCtx, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	// oauth2
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	idTokenVerifier := oidcProvider.Verifier(&oidc.Config{
		ClientID:        cfg.ClientID,
		SkipIssuerCheck: true,
	})
	op := &OIDCProvider{
		Provider:        oidcProvider,
		IDTokenVerifier: idTokenVerifier,
		Oauth2Config:    oauthCfg,
	}
	return op, nil
}

func configHandler(logger *slog.Logger, session sessions.Store, httpClient *http.Client) http.HandlerFunc {
	templates := []string{
		"template/base.gohtml",
		"template/config.gohtml",
	}
	tpl := template.Must(template.New("").ParseFS(tplEmbed, templates...))
	return func(w http.ResponseWriter, r *http.Request) {
		s, _ := session.Get(r, sessionName)
		var errorMessage string
		var showError bool
		if r.Method != http.MethodPost {
			errorMessage, showError = s.Values[sessionErrorMessageKey].(string)
			if showError {
				delete(s.Values, sessionErrorMessageKey)
				_ = session.Save(r, w, s)
			}
			storedCfg, ok := cfgStore.Load(storeOIDCProviderConfigKey)
			if !ok {
				storedCfg = &OIDCConfig{
					RedirectURL: fmt.Sprintf("http://%s%s", r.Host, callbackHandlerPath),
				}
			}
			cfg := storedCfg.(*OIDCConfig)
			err := tpl.ExecuteTemplate(w, "base.gohtml", map[string]any{
				"cfg": *cfg,
				//
				"configPath":   configHandlerPath,
				"showError":    showError,
				"errorMessage": errorMessage,
			})
			if err != nil {
				logger.Error("config: execute template failed", slog.Any("error", err))
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		r = r.WithContext(oidc.ClientContext(r.Context(), httpClient))
		// POST
		if err := r.ParseForm(); err != nil {
			logger.Error("config: parse form failed", slog.Any("error", err))
			s.Values[sessionErrorMessageKey] = "Failed to parse submitted form"
			_ = session.Save(r, w, s)
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
			return
		}
		cfg := &OIDCConfig{
			IssuerURL:    strings.TrimSpace(r.FormValue("issuer_url")),
			ClientID:     strings.TrimSpace(r.FormValue("client_id")),
			ClientSecret: strings.TrimSpace(r.FormValue("client_secret")),
			RedirectURL:  strings.TrimSpace(r.FormValue("redirect_url")),
		}
		if err := cfg.validate(); err != nil {
			logger.Error("config: OIDC config failed", slog.Any("error", err))
			s.Values[sessionErrorMessageKey] = err.Error()
			_ = session.Save(r, w, s)
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
			return
		}
		logger.Debug("config: validating OIDC provider", "payload", *cfg)
		op, err := cfg.Provider(r.Context(), httpClient)
		if err != nil {
			logger.Error("config: OIDC config failed", slog.Any("error", err))
			s.Values[sessionErrorMessageKey] = err.Error()
			_ = session.Save(r, w, s)
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
			return
		}
		var providerInfo map[string]any
		if err = op.Provider.Claims(&providerInfo); err != nil {
			logger.Error("index: Failed to parse provider info claim", "error", err)
			http.Error(w, "index: "+err.Error(), http.StatusInternalServerError)
			return
		}
		providerInfoJSON, _ := json.MarshalIndent(providerInfo, "", "  ")
		// following config could be reset from logout handler
		cfgStore.Delete(sessionValueTokenKey) // delete any previous token
		cfgStore.Store(storeOIDCProviderConfigKey, cfg)
		cfgStore.Store(storeOIDCProviderKey, op)
		cfgStore.Store(storeOIDCProviderInfoKey, string(providerInfoJSON))
		logger.Info("config: OIDC config setup success")
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func logoutHandler(logger *slog.Logger, session sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resetConfig, _ := strconv.ParseBool(strings.TrimSpace(strings.ToLower(r.URL.Query().Get("reset_config"))))
		s, _ := session.Get(r, sessionName)
		if s != nil {
			logger.Debug("logout: reset session")
			s.Values = nil
		}
		_ = session.Save(r, w, s)
		cfgStore.Delete(sessionValueTokenKey) // delete token
		if resetConfig {
			logger.Debug("logout: reset provider config")
			// it was set from config handler
			cfgStore.Delete(storeOIDCProviderConfigKey)
			cfgStore.Delete(storeOIDCProviderKey)
			cfgStore.Delete(storeOIDCProviderInfoKey)
			// back to config
			http.Redirect(w, r, configHandlerPath, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

type OIDCProvider struct {
	Provider        *oidc.Provider
	IDTokenVerifier *oidc.IDTokenVerifier
	Oauth2Config    *oauth2.Config
}

func (op *OIDCProvider) redirectToAuth(w http.ResponseWriter, r *http.Request, opts ...oauth2.AuthCodeOption) {
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	state := base64.RawURLEncoding.EncodeToString(rnd[:])
	oauth2URL := op.Oauth2Config.AuthCodeURL(state, opts...)
	http.Redirect(w, r, oauth2URL, http.StatusFound)
}

func sessionStore() sessions.Store {
	var sessionKey [16]byte
	if _, err := rand.Read(sessionKey[:]); err != nil {
		panic(err)
	}
	session := sessions.NewCookieStore(sessionKey[:])
	session.Options.Secure = false
	session.Options.HttpOnly = true
	return session
}

// loggedHTTPClientTransport is a simple transport to log outgoing HTTP client call.
type loggedHTTPClientTransport struct {
	logger    *slog.Logger
	transport http.RoundTripper
}

func (t *loggedHTTPClientTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	res, err := t.transport.RoundTrip(r)
	var statusCode int
	if res != nil {
		statusCode = res.StatusCode
	}
	t.logger.Info("HTTP client call",
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.Float64("duration", float64(time.Since(start).Nanoseconds()/1e6)),
		slog.Int("status", statusCode),
		slog.Any("error", err),
	)
	return res, err
}

func main() {
	addr := strings.TrimSpace(os.Getenv("SERVER_ADDRESS"))
	if addr == "" {
		addr = "0.0.0.0:3000"
	}
	// logBuffer will be used for logs view in the UI.
	logBuffer := &bytes.Buffer{}
	logOutput := io.MultiWriter(logBuffer, os.Stdout)
	// logger
	loggerOptions := &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key != slog.TimeKey {
				return a
			}
			a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
			return a
		},
	}
	logger := slog.New(slog.NewJSONHandler(logOutput, loggerOptions))
	// session storage
	gob.Register((*oauth2.Token)(nil))
	session := sessionStore()
	httpClient := &http.Client{
		Transport: &loggedHTTPClientTransport{logger: logger, transport: http.DefaultTransport},
		Timeout:   time.Second * 30,
	}
	// HTTP handler
	handler := http.NewServeMux()
	handler.HandleFunc("/", indexHandler(logger, session, httpClient, logBuffer))
	handler.HandleFunc(logoutHandlerPath, logoutHandler(logger, session))
	handler.HandleFunc(configHandlerPath, configHandler(logger, session, httpClient))
	handler.HandleFunc(callbackHandlerPath, callbackHandler(logger, session, httpClient))
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
	}
	logger.Info("Starting HTTP server", slog.String("addr", httpServer.Addr))
	if err := httpServer.ListenAndServe(); err != nil {
		logger.Error("Failed to start HTTP server", "error", err)
	}
}
