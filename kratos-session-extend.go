package kratos_session_extend

import (
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strconv"
    "strings"
    "text/template"
    "time"
)

// Config the plugin configuration.
type Config struct {
    CacheSeconds      int
    SessionCookie     string
    LastRefreshedCookie string
    CookieDomain string
    IdentityApiBaseUrl string
    AdminApiBaseUrl   string
    SigningKey string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
    return &Config{
        CacheSeconds:      300,
        SessionCookie:     "my_session",
        LastRefreshedCookie: "my_session_last_refreshed",
        CookieDomain: "127.0.0.1",
        IdentityApiBaseUrl: "http://127.0.0.1:4433",
        AdminApiBaseUrl:   "http://127.0.0.1:4434",
        SigningKey: "dangerous_change_me",
    }
}

type KratosSessionExtend struct {
    next              http.Handler
    cacheSeconds      int
    sessionCookie     string
    lastRefreshedCookie string
    cookieDomain string
    identityApiBaseUrl string
    adminApiBaseUrl   string
    signingKey []uint8
    name              string
    template          *template.Template
}

type Session struct {
    ID     string `json:"id"`
    Active bool   `json:"active"`
    ExpiresAt string `json:"expires_at"`
    KratosCookies []*http.Cookie
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    signingKey := []byte(config.SigningKey)
    return &KratosSessionExtend{
        cacheSeconds:      config.CacheSeconds,
        sessionCookie:     config.SessionCookie,
        lastRefreshedCookie: config.LastRefreshedCookie,
        cookieDomain: config.CookieDomain,
        identityApiBaseUrl: config.IdentityApiBaseUrl,
        adminApiBaseUrl:   config.AdminApiBaseUrl,
        signingKey: signingKey,
        next:              next,
        name:              name,
        template:          template.New("demo").Delims("[[", "]]"),
    }, nil
}

func (a *KratosSessionExtend) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    sessionCookie, err := req.Cookie(a.sessionCookie)
    authHeader := req.Header.Get("Authorization")
    authFields := strings.Fields(authHeader)
    authToken := ""

    if len(authFields) == 2 && strings.ToLower(authFields[0]) == "bearer" {
        authToken = authFields[1]
    }

    // Proceed to the next handler if there is no session cookie nor token
    if err != nil && authToken == "" {
        a.next.ServeHTTP(rw, req)
        return
    }

    then := time.Now().Add(-time.Duration(a.cacheSeconds) * time.Second)

    lastRefreshedCookie, err := req.Cookie(a.lastRefreshedCookie)

    // Proceed to the next handler if there is no cache cookie & set it for the next request
    if err != nil || lastRefreshedCookie.Value == "" {
        fmt.Println("lastRefreshedCookie no value")
        a.setCacheCookie(rw, nil)
        a.next.ServeHTTP(rw, req)
        return
    }

    cookieParts := strings.Split(lastRefreshedCookie.Value, "|")

    // Proceed to the next handler if the cache cookie is incorrectly formatted. & set it for the next request
    if len(cookieParts) != 2 {
        fmt.Println("lastRefreshedCookie incorrect format")
        a.setCacheCookie(rw, nil)
        a.next.ServeHTTP(rw, req)
        return
    }

    // Proceed to the next handler if signature verification failed & set it for the next request
    if !a.verifyValue(cookieParts[0], cookieParts[1]) {
        fmt.Println("lastRefreshedCookie signature failed")
        a.setCacheCookie(rw, nil)
        a.next.ServeHTTP(rw, req)
        return
    }

    i, err := strconv.ParseInt(cookieParts[0], 10, 64)

    // Proceed to the next handler if the cache cookie timestamp is invalid & set it properly for the next request
    if err != nil || i == 0 {
        fmt.Println("lastRefreshedCookie timestamp parse failed")
        a.setCacheCookie(rw, nil)
        a.next.ServeHTTP(rw, req)
        return
    }

    sessionLastRefreshed := time.Unix(i, 0)

    // Confirm that the cacheSeconds has passed before extending the session
    if sessionLastRefreshed.Before(then) {
        session, err := a.getSession(sessionCookie, authToken)
        if err != nil {
            fmt.Println("getSession error:", err)
            a.next.ServeHTTP(rw, req)
            return
        }

        // Confirm that the session is active before extending the session
        if session.Active {
            if a.extendSession(session) {
                session, err := a.getSession(sessionCookie, authToken)
                if err != nil {
                    fmt.Println("getSession error:", err)
                    a.next.ServeHTTP(rw, req)
                    return
                }

                a.setExtendedSessionCookie(rw, sessionCookie, session)

                // Set the cache cookie now that we have extended the session
                a.setCacheCookie(rw, &session)

            }
        }
    }

    // Proceed to the next handler, we're done!
    a.next.ServeHTTP(rw, req)
}

func (a *KratosSessionExtend) getSession(sessionCookie *http.Cookie, authToken string) (Session, error) {
    client := &http.Client{}
    url := fmt.Sprintf("%s/sessions/whoami", a.identityApiBaseUrl)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return Session{}, fmt.Errorf("creating request: %w", err)
    }

    if sessionCookie != nil {
        req.AddCookie(sessionCookie)
    }
    if authToken != "" {
        req.Header.Add("Authorization", "Bearer "+authToken)
    }
    req.Header.Add("Content-Type", "application/json; charset=utf-8")

    resp, err := client.Do(req)
    if err != nil {
        return Session{}, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return Session{}, fmt.Errorf("unexpected status: %s", resp.Status)
    }

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return Session{}, fmt.Errorf("reading response body: %w", err)
    }

    var session Session
    if err := json.Unmarshal(respBody, &session); err != nil {
        return session, fmt.Errorf("unmarshaling response body: %w", err)
    }

    session.KratosCookies = resp.Cookies()

    return session, nil
}

func (a *KratosSessionExtend) extendSession(session Session) bool {
    client := &http.Client{}
    url := fmt.Sprintf("%s/sessions/%s/extend", a.adminApiBaseUrl, session.ID)
    req, err := http.NewRequest("PATCH", url, nil)
    if err != nil {
        fmt.Println("Failure creating request:", err)
        return false
    }

    req.Header.Add("Content-Type", "application/json; charset=utf-8")

    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Failure making request:", err)
        return false
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        fmt.Println("Unexpected status:", resp.Status)
        return false
    }

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("Reading response body failed:", err)
        return false
    }

    var extendSession Session
    if err := json.Unmarshal(respBody, &extendSession); err != nil {
        fmt.Println("Unmarshaling response body failed:", err)
        return false
    }

    return true
}

func (a *KratosSessionExtend) setCacheCookie(rw http.ResponseWriter, session *Session) {
    nowUnixTimestamp := strconv.Itoa(int(time.Now().Unix()))
    // Create the signed value
    signedValue := a.signValue(nowUnixTimestamp)
    cookieValue := fmt.Sprintf("%s|%s", nowUnixTimestamp, signedValue)

    var expires time.Time
    var err error

    if session != nil {
        expires, err = time.Parse("2006-01-02T15:04:05.999999Z", session.ExpiresAt)
        if err != nil {
            fmt.Println("Error parsing time:", err)
            fmt.Println("Timestamp string:", session.ExpiresAt)
            return
        }
    }

    http.SetCookie(rw, &http.Cookie{
        Name:     a.lastRefreshedCookie,
        Value:    cookieValue,
        Path:     "/",
        HttpOnly: true,
        // Secure:   true, // Ensure cookie is only transmitted over HTTPS
        SameSite: http.SameSiteLaxMode,
        Domain: a.cookieDomain,
        Expires: expires,
    })

}

func (a *KratosSessionExtend) setExtendedSessionCookie(rw http.ResponseWriter, sessionCookie *http.Cookie, session Session) {
    // Update the cookie in the response writer
    for _, cookie := range session.KratosCookies {
        http.SetCookie(rw, cookie)
    }
}

func (a *KratosSessionExtend) signValue(value string) string {
    h := hmac.New(sha256.New, a.signingKey)
    h.Write([]byte(value))
    return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (a *KratosSessionExtend) verifyValue(value, signature string) bool {
    decodedSignature, err := base64.StdEncoding.DecodeString(signature)
    if err != nil {
        return false
    }

    h := hmac.New(sha256.New, a.signingKey)
    h.Write([]byte(value))
    expectedSignature := h.Sum(nil)

    return hmac.Equal(expectedSignature, decodedSignature)
}