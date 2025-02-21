package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// User model
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique" json:"username"`
	Password string `json:"password"`
}

// Database instance
var DB *gorm.DB

// Load environment variables
func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️ Warning: No .env file found, using system environment variables.")
	}
}

// Connect to PostgreSQL
func connectDB() {
	var err error
	DB, err = gorm.Open(postgres.Open(os.Getenv("DB_URI")), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}
	fmt.Println("✅ Connected to Database")

	// Auto-migrate the User table
	DB.AutoMigrate(&User{})
}

// Hash password before saving user
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Compare hashed password
func checkPassword(hashedPwd, plainPwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(plainPwd))
	return err == nil
}

// Generate JWT Token
func generateToken(userID uint) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 1-day expiration
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

// Signup Handler
func signup(c *fiber.Ctx) error {
	var user User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Hash the password
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to hash password"})
	}
	user.Password = hashedPassword

	// Save user in DB
	result := DB.Create(&user)
	if result.Error != nil {
		return c.Status(400).JSON(fiber.Map{"error": "User already exists"})
	}

	return c.JSON(fiber.Map{"message": "User registered successfully"})
}

// Login Handler
func login(c *fiber.Ctx) error {
	var input User
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Find user by username
	var user User
	result := DB.Where("username = ?", input.Username).First(&user)
	if result.Error != nil {
		return c.Status(400).JSON(fiber.Map{"error": "User not found"})
	}

	// Compare passwords
	if !checkPassword(user.Password, input.Password) {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Generate JWT token
	token, err := generateToken(user.ID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.JSON(fiber.Map{"token": token})
}

// JWT Middleware
func authMiddleware(c *fiber.Ctx) error {
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return c.Status(401).JSON(fiber.Map{"error": "Token required"})
	}

	// Parse JWT token
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid token"})
	}

	// Set user ID in context
	c.Locals("user_id", claims["user_id"])
	return c.Next()
}

// Protected Route
func protectedRoute(c *fiber.Ctx) error {
	userID := c.Locals("user_id")
	return c.JSON(fiber.Map{"message": "Welcome to the protected route!", "user_id": userID})
}

func main() {
	connectDB()

	app := fiber.New()

	// Authentication routes
	app.Post("/signup", signup)
	app.Post("/login", login)

	// Protected route (Requires JWT)
	app.Get("/protected", authMiddleware, protectedRoute)

	fmt.Println("🚀 Server running on http://localhost:3000/")
	log.Fatal(app.Listen(":3000"))
}
