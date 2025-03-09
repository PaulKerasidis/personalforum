package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in our system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // Never expose password in JSON
}

// Session represents an active user session
type Session struct {
	Token     string    `json:"token"`
	UserID    int       `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Server encapsulates the HTTP server and its dependencies
type Server struct {
	db      *sql.DB
	mux     *http.ServeMux
	tmpl    *template.Template
	server  *http.Server
	sessions map[string]Session
}

// Initialize the database schema
func initDB(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		created_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	`)
	return err
}

// NewServer creates and initializes a new server instance
func NewServer() (*Server, error) {
	// Initialize SQLite database
	db, err := sql.Open("sqlite3", "./auth.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	
	if err := initDB(db); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	
	// Parse HTML templates
	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		// If templates don't exist, create an empty template
		tmpl = template.New("empty")
	}
	
	// Initialize server
	s := &Server{
		db:       db,
		mux:      http.NewServeMux(),
		tmpl:     tmpl,
		sessions: make(map[string]Session),
	}
	
	// Register routes
	s.routes()
	
	// Create HTTP server
	s.server = &http.Server{
		Addr:         ":8080",
		Handler:      s.mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Load sessions from database
	if err := s.loadSessions(); err != nil {
		return nil, fmt.Errorf("failed to load sessions: %w", err)
	}
	
	return s, nil
}

// loadSessions loads active sessions from the database into memory
func (s *Server) loadSessions() error {
	rows, err := s.db.Query("SELECT token, user_id, created_at, expires_at FROM sessions WHERE expires_at > datetime('now')")
	if err != nil {
		return err
	}
	defer rows.Close()
	
	for rows.Next() {
		var sess Session
		var createdStr, expiresStr string
		
		if err := rows.Scan(&sess.Token, &sess.UserID, &createdStr, &expiresStr); err != nil {
			return err
		}
		
		sess.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		sess.ExpiresAt, _ = time.Parse(time.RFC3339, expiresStr)
		
		// Only store non-expired sessions
		if sess.ExpiresAt.After(time.Now()) {
			s.sessions[sess.Token] = sess
		}
	}
	
	return rows.Err()
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Start the server in a goroutine
	go func() {
		fmt.Printf("Server started on \033]8;;http://localhost:8080/\033\\http://localhost:8080/\033]8;;\033\\\n")
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()
	
	// Create a channel to listen for interrupt signals
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	
	// Block until we receive a termination signal
	<-done
	log.Println("Server is shutting down...")
	
	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Attempt graceful shutdown
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}
	
	log.Println("Server exited gracefully")
	return nil
}

// Close closes the database connection
func (s *Server) Close() error {
	return s.db.Close()
}

// routes registers all the HTTP routes
func (s *Server) routes() {
	// Static files
	s.mux.HandleFunc("GET /", s.handleHome())
	s.mux.HandleFunc("GET /login", s.handleLoginPage())
	s.mux.HandleFunc("GET /register", s.handleRegisterPage())
	
	// API endpoints
	s.mux.HandleFunc("POST /api/register", s.handleRegister())
	s.mux.HandleFunc("POST /api/login", s.handleLogin())
	s.mux.HandleFunc("POST /api/logout", s.handleLogout())
	
	// Protected routes
	s.mux.HandleFunc("GET /dashboard", s.authenticated(s.handleDashboard()))
}

// Middleware for authentication
func (s *Server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session token from cookie
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		// Check if session exists and is valid
		session, exists := s.sessions[cookie.Value]
		if !exists || session.ExpiresAt.Before(time.Now()) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		// Session is valid, proceed
		next(w, r)
	}
}

// Get user from session
func (s *Server) getUserFromSession(r *http.Request) (*User, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, err
	}
	
	session, exists := s.sessions[cookie.Value]
	if !exists || session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("invalid session")
	}
	
	var user User
	err = s.db.QueryRow("SELECT id, username FROM users WHERE id = ?", session.UserID).Scan(&user.ID, &user.Username)
	if err != nil {
		return nil, err
	}
	
	return &user, nil
}

// Handlers
func (s *Server) handleHome() http.HandlerFunc {
	// For simplicity, we'll use a string template instead of a file
	homeHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Auth Server</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        nav { margin-bottom: 20px; }
        nav a { margin-right: 15px; }
    </style>
</head>
<body>
    <h1>Welcome to Auth Server</h1>
    <nav>
        <a href="/login">Login</a>
        <a href="/register">Register</a>
        <a href="/dashboard">Dashboard (Protected)</a>
    </nav>
    <p>This is a simple authentication server built with Go.</p>
</body>
</html>`

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, homeHTML)
	}
}

func (s *Server) handleLoginPage() http.HandlerFunc {
	loginHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        form { display: flex; flex-direction: column; width: 300px; }
        input { margin-bottom: 10px; padding: 8px; }
        button { padding: 10px; background: #4CAF50; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Login</h1>
    <form id="loginForm">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="/register">Register</a></p>
    <div id="message"></div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: formData.get('username'),
                    password: formData.get('password'),
                }),
            });
            
            const result = await response.json();
            const messageEl = document.getElementById('message');
            
            if (response.ok) {
                messageEl.textContent = 'Login successful! Redirecting...';
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            } else {
                messageEl.textContent = result.error || 'Login failed';
            }
        });
    </script>
</body>
</html>`

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, loginHTML)
	}
}

func (s *Server) handleRegisterPage() http.HandlerFunc {
	registerHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        form { display: flex; flex-direction: column; width: 300px; }
        input { margin-bottom: 10px; padding: 8px; }
        button { padding: 10px; background: #4CAF50; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Register</h1>
    <form id="registerForm">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="/login">Login</a></p>
    <div id="message"></div>
    
    <script>
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: formData.get('username'),
                    password: formData.get('password'),
                }),
            });
            
            const result = await response.json();
            const messageEl = document.getElementById('message');
            
            if (response.ok) {
                messageEl.textContent = 'Registration successful! Redirecting to login...';
                setTimeout(() => {
                    window.location.href = '/login';
                }, 1000);
            } else {
                messageEl.textContent = result.error || 'Registration failed';
            }
        });
    </script>
</body>
</html>`

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, registerHTML)
	}
}

func (s *Server) handleDashboard() http.HandlerFunc {
	dashboardHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        button { padding: 10px; background: #f44336; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Dashboard</h1>
    <p>Welcome, {{.Username}}! This is a protected page.</p>
    <button id="logoutBtn">Logout</button>
    
    <script>
        document.getElementById('logoutBtn').addEventListener('click', async () => {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/';
        });
    </script>
</body>
</html>`

	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))

	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.getUserFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		w.Header().Set("Content-Type", "text/html")
		tmpl.Execute(w, user)
	}
}

// API handlers
func (s *Server) handleRegister() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	type response struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, response{Success: false, Error: "Invalid request format"}, http.StatusBadRequest)
			return
		}
		
		// Validate input
		if req.Username == "" || req.Password == "" {
			sendJSON(w, response{Success: false, Error: "Username and password are required"}, http.StatusBadRequest)
			return
		}
		
		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			sendJSON(w, response{Success: false, Error: "Internal server error"}, http.StatusInternalServerError)
			return
		}
		
		// Save user to database
		_, err = s.db.Exec("INSERT INTO users (username, password) VALUES (?, ?)",
			req.Username, string(hashedPassword))
		
		if err != nil {
			log.Printf("Failed to register user: %v", err)
			sendJSON(w, response{Success: false, Error: "Username already exists"}, http.StatusConflict)
			return
		}
		
		sendJSON(w, response{Success: true}, http.StatusCreated)
	}
}

func (s *Server) handleLogin() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	type response struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, response{Success: false, Error: "Invalid request format"}, http.StatusBadRequest)
			return
		}
		
		// Find user
		var user User
		var hashedPassword string
		err := s.db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", req.Username).
			Scan(&user.ID, &user.Username, &hashedPassword)
		
		if err != nil {
			sendJSON(w, response{Success: false, Error: "Invalid username or password"}, http.StatusUnauthorized)
			return
		}
		
		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
			sendJSON(w, response{Success: false, Error: "Invalid username or password"}, http.StatusUnauthorized)
			return
		}
		
		// Create session
		token := uuid.New().String()
		expiresAt := time.Now().Add(24 * time.Hour) // 24-hour session
		
		session := Session{
			Token:     token,
			UserID:    user.ID,
			CreatedAt: time.Now(),
			ExpiresAt: expiresAt,
		}
		
		// Store session in database
		_, err = s.db.Exec(
			"INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
			session.Token, session.UserID, session.CreatedAt.Format(time.RFC3339), session.ExpiresAt.Format(time.RFC3339),
		)
		
		if err != nil {
			log.Printf("Failed to create session: %v", err)
			sendJSON(w, response{Success: false, Error: "Failed to create session"}, http.StatusInternalServerError)
			return
		}
		
		// Store session in memory
		s.sessions[token] = session
		
		// Set cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    token,
			Expires:  expiresAt,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		
		sendJSON(w, response{Success: true}, http.StatusOK)
	}
}

func (s *Server) handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session token from cookie
		cookie, err := r.Cookie("session")
		if err == nil {
			// Delete session from memory
			delete(s.sessions, cookie.Value)
			
			// Delete session from database
			s.db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
		}
		
		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			MaxAge:   -1,
			Path:     "/",
			HttpOnly: true,
		})
		
		sendJSON(w, map[string]bool{"success": true}, http.StatusOK)
	}
}

// Helper function to send JSON responses
func sendJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func main() {
	// Create and initialize server
	server, err := NewServer()
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}
	defer server.Close()
	
	// Start the server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}