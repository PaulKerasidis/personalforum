package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// User represents a user in our system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Age      int    `json:"age"`
}

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create users table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		age INTEGER
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Database initialized successfully")
}

// Handler functions
func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Insert user into database
	stmt, err := db.Prepare("INSERT INTO users(username, email, age) VALUES(?, ?, ?)")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(user.Username, user.Email, user.Age)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	user.ID = int(id)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query("SELECT id, username, email, age FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Age)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID parameter is required", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, username, email, age FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Age)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "ID parameter is required", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}

	var user User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.ID = id

	// Update user in database
	stmt, err := db.Prepare("UPDATE users SET username = ?, email = ?, age = ? WHERE id = ?")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Username, user.Email, user.Age, user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID parameter is required", http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare("DELETE FROM users WHERE id = ?")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RequestTracker keeps track of active requests
type RequestTracker struct {
	wg      sync.WaitGroup
	mu      sync.Mutex
	active  map[string]bool
	timeout time.Duration
}

// NewRequestTracker creates a new request tracker
func NewRequestTracker(timeout time.Duration) *RequestTracker {
	return &RequestTracker{
		active:  make(map[string]bool),
		timeout: timeout,
	}
}

// Add registers a new request with a unique ID
func (rt *RequestTracker) Add(id string) {
	rt.mu.Lock()
	rt.active[id] = true
	rt.mu.Unlock()
	rt.wg.Add(1)
}

// Done marks a request as completed
func (rt *RequestTracker) Done(id string) {
	rt.mu.Lock()
	delete(rt.active, id)
	rt.mu.Unlock()
	rt.wg.Done()
}

// Wait waits for all active requests to complete with timeout
func (rt *RequestTracker) Wait() bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		rt.wg.Wait()
	}()

	select {
	case <-c:
		return true // All requests completed
	case <-time.After(rt.timeout):
		return false // Timed out
	}
}

// ActiveRequests returns number of active requests
func (rt *RequestTracker) ActiveRequests() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.active)
}

// middleware for tracking requests
func requestTrackerMiddleware(tracker *RequestTracker, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate a unique request ID (could use UUID in production)
		requestID := fmt.Sprintf("%s-%d", r.URL.Path, time.Now().UnixNano())

		// Register request in tracker
		tracker.Add(requestID)
		defer tracker.Done(requestID)

		// Process the request in a goroutine
		done := make(chan bool)

		go func() {
			next(w, r)
			close(done)
		}()

		// Wait for completion or context cancellation
		select {
		case <-done:
			// Request completed normally
			return
		case <-r.Context().Done():
			// Request was cancelled by client or server shutdown
			log.Printf("Request %s cancelled or server shutting down", requestID)
			return
		}
	}
}

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	// Create request tracker with 30 second timeout for graceful shutdown
	tracker := NewRequestTracker(30 * time.Second)

	// Create a custom server
	server := &http.Server{
		Addr:    ":8080",
		Handler: nil, // Using default ServeMux
	}

	// Register handlers with middleware
	http.HandleFunc("/users", requestTrackerMiddleware(tracker, getUsers))
	http.HandleFunc("/user", requestTrackerMiddleware(tracker, getUser))
	http.HandleFunc("/user/create", requestTrackerMiddleware(tracker, createUser))
	http.HandleFunc("/user/update", requestTrackerMiddleware(tracker, updateUser))
	http.HandleFunc("/user/delete", requestTrackerMiddleware(tracker, deleteUser))

	// Start server in a goroutine
	go func() {
		fmt.Println("Server starting on port 8080...")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Set up channel to listen for interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Block until interrupt signal is received
	<-stop

	// Begin graceful shutdown
	log.Println("Shutting down server...")

	// Create a deadline context for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Notify server to stop accepting new connections
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	// Wait for active requests to complete
	log.Printf("Waiting for %d active requests to complete...", tracker.ActiveRequests())
	if completed := tracker.Wait(); completed {
		log.Println("All requests completed successfully")
	} else {
		log.Println("Timeout waiting for requests to complete")
	}

	log.Println("Server gracefully stopped")
}
