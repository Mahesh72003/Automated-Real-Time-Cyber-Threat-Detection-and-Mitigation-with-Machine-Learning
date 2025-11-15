import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re

# Dataset of SQL injection patterns (in your case, you can load this from a file)
# Full dataset of 200 entries (100 SQLi and 100 normal queries)
# Correct the size of the data list by ensuring it has 200 entries

# SQL Injection queries (100 entries)
def is_email(query):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, query) is not None

# Function to count occurrences of special characters
def count_special_characters(query):
    special_chars = ["'", "\"", ";", "--", "#", "*", "(", ")", "@", "%"]
    return sum(query.count(char) for char in special_chars)

data = [
    "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 --", "\" OR 1=1 --", "OR 1=1 --",
    "' OR 'a'='a", "\" OR \"a\"=\"a", "' UNION SELECT 1,2,3 --", "\" UNION SELECT 1,2,3 --",
    "' UNION SELECT null, username, password FROM users --", "\" UNION SELECT null, username, password FROM users --",
    "' UNION ALL SELECT 1,2,3,4,5 --", "\" UNION ALL SELECT 1,2,3,4,5 --", "' AND 1=CONVERT(int, (SELECT @@version)) --",
    "\" AND 1=CONVERT(int, (SELECT @@version)) --", "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "\" AND (SELECT COUNT(*) FROM users) > 0 --", "' OR IF(1=1, SLEEP(5), 0) --", "\" OR IF(1=1, SLEEP(5), 0) --",
    "' OR 1=1; WAITFOR DELAY '0:0:5' --", "\" OR 1=1; WAITFOR DELAY '0:0:5' --", "' AND '1'='1 --", "\" AND \"1\"=\"1 --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --", "\" AND (SELECT COUNT(*) FROM users) > 0 --", "' OR '1'='1' #",
    "\" OR \"1\"=\"1\" #", "' OR '1'='1' --", "\" OR \"1\"=\"1\" --", "admin' --", "admin\" --", "admin' #", "admin\" #",
    "'; DROP TABLE users --", "\"; DROP TABLE users --", "'; INSERT INTO users(username,password) VALUES ('attacker','hacked') --",
    "\"; INSERT INTO users(username,password) VALUES ('attacker','hacked') --", "' OR '1'='1' --", "\" OR \"1\"=\"1\" --",
    "' OR 'x'='x' #", "\" OR \"x\"=\"x\" #", "0x27 OR 1=1 --", "0x22 OR 1=1 --", "UNION SELECT char(117,115,101,114), char(112,97,115,115) --",
    "' OR '1'='1' --", "\" OR \"1\"=\"1\" --", "' OR 'a'='a' --", "\" OR \"a\"=\"a\" --", "' OR 1=1; --", "\" OR 1=1; --",
    "' UNION SELECT null, username, password FROM users --", "\" UNION SELECT null, username, password FROM users --",
    "' AND 1=CONVERT(int, (SELECT @@version)) --", "\" AND 1=CONVERT(int, (SELECT @@version)) --", "' OR 1=1 --", "\" OR 1=1 --",
    "UNION SELECT 1,2,3,4 --", "\" UNION SELECT 1,2,3,4 --", "' AND (SELECT COUNT(*) FROM users) > 0 --", "\" AND (SELECT COUNT(*) FROM users) > 0 --",
    "' UNION SELECT * FROM users --", "\" UNION SELECT * FROM users --", "' OR 1=1 --", "\" OR 1=1 --",
    "' AND 1=CONVERT(int, (SELECT @@version)) --", "\" AND 1=CONVERT(int, (SELECT @@version)) --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --", "\" AND (SELECT COUNT(*) FROM users) > 0 --", "' OR 1=1' #", "\" OR 1=1\" #",
    "' UNION SELECT * FROM users --", "\" UNION SELECT * FROM users --", "' AND 1=CONVERT(int, (SELECT @@version)) --",
    "\" AND 1=CONVERT(int, (SELECT @@version)) --", "' OR IF(1=1, SLEEP(5), 0) --", "\" OR IF(1=1, SLEEP(5), 0) --","'; DROP TABLE products --", "admin' --", "1' OR 'a'='a' --", "OR 1=1; DROP DATABASE --", "';--",
    "1' OR 1=1 --", "' OR 1=1 --", "UNION SELECT username, password FROM users --", "SELECT * FROM information_schema.tables --",
    "UNION SELECT null, username, password, email FROM users --", "1' OR 1=1 LIMIT 1 --", "' OR 1=1 --",
    "DROP TABLE employees --", "' AND 1=1 --", "\" OR 1=1 --", "' OR '1'='1'; --", "' OR '1'='1' --",
    "UNION SELECT 1, 2, 3 FROM dual --", "OR 1=1 --", "SELECT * FROM users WHERE username='admin' --",
    "' OR '1'='1' --", "\" OR \"1\"=\"1\" --", "' OR 1=1 --", "UNION ALL SELECT 1,2,3,4 --", "DROP TABLE customers --",
    "SELECT * FROM products WHERE name='admin' --", "1' OR 1=1 --", "UNION SELECT password FROM users WHERE username='admin' --",
    "' OR 'a'='a'; --", "SELECT name, email FROM customers WHERE email LIKE '%@gmail.com' --", "' OR 1=1; --",
    "' OR '1'='1' --", "UNION SELECT * FROM orders --", "SELECT id FROM users WHERE username='admin' --", "SELECT * FROM users --","SELECT * FROM users;", "SELECT id, name FROM products WHERE price > 100;", "SELECT name, age FROM employees WHERE department='HR';",
    "SELECT * FROM orders WHERE order_date = '2025-01-01';", "SELECT name, department FROM employees WHERE department='IT';",
    "SELECT COUNT(*) FROM users;", "SELECT id, name FROM products WHERE price BETWEEN 50 AND 200;",
    "UPDATE users SET password='newpassword' WHERE username='admin';", "INSERT INTO orders (product_id, quantity) VALUES (1, 10);",
    "SELECT AVG(price) FROM products WHERE category='Electronics';", "SELECT name, email FROM customers WHERE country='USA';",
    "DELETE FROM users WHERE id=5;", "SELECT * FROM employees WHERE hire_date > '2020-01-01';",
    "SELECT id, name FROM products ORDER BY price DESC;", "SELECT DISTINCT department FROM employees;",
    "SELECT COUNT(*) FROM orders WHERE order_status='Shipped';", "UPDATE products SET stock_quantity=stock_quantity - 1 WHERE product_id=101;",
    "SELECT id, name FROM employees WHERE department='Finance';", "SELECT product_name, stock_quantity FROM products WHERE stock_quantity < 5;",
    "SELECT MAX(price) FROM products;", "SELECT name FROM customers WHERE customer_id=10;", "SELECT id, name, address FROM suppliers WHERE country='USA';",
    "SELECT SUM(total_price) FROM orders WHERE order_date BETWEEN '2025-01-01' AND '2025-12-31';",
    "SELECT * FROM sales WHERE region='North America';", "SELECT id, name FROM customers WHERE email LIKE '%@gmail.com';",
    "INSERT INTO employees (name, department, salary) VALUES ('John Doe', 'HR', 50000);", "SELECT * FROM products WHERE category='Furniture';",
    "SELECT name, price FROM products WHERE price < 100;", "SELECT department, COUNT(*) FROM employees GROUP BY department;",
    "UPDATE users SET email='newemail@example.com' WHERE id=10;", "SELECT id, name FROM customers WHERE country='Canada';",
    "SELECT address FROM suppliers WHERE supplier_id=7;", "SELECT name FROM employees WHERE job_title='Manager';",
    "SELECT COUNT(*) FROM orders WHERE status='Pending';", "INSERT INTO customers (name, email, country) VALUES ('Jane Smith', 'jane@example.com', 'UK');",
    "SELECT COUNT(*) FROM products WHERE price > 200;","mahesh@2003","maheshvanjre@yahoo.com", "SELECT product_name, price FROM products WHERE price BETWEEN 150 AND 500;",
    "SELECT * FROM employees WHERE salary > 40000;", "SELECT name, email FROM customers WHERE country='Germany';",
    "SELECT COUNT(*) FROM orders WHERE order_date > '2025-01-01';", "SELECT id, name FROM customers WHERE registration_date BETWEEN '2025-01-01' AND '2025-12-31';",
    "SELECT department FROM employees WHERE salary > 60000;", "UPDATE products SET price=price * 1.1 WHERE category='Clothing';",
    "SELECT name FROM employees WHERE department='Marketing';", "SELECT * FROM customers WHERE city='New York';",
    "SELECT id, name FROM orders WHERE customer_id=3;", "SELECT * FROM suppliers WHERE city='London';",
    "SELECT COUNT(*) FROM products WHERE category='Electronics';","Haridra@2003", "SELECT MAX(salary) FROM employees;",
    "SELECT * FROM employees WHERE department='Sales' AND salary > 30000;", "SELECT DISTINCT department FROM employees WHERE hire_date > '2018-01-01';",
    "SELECT product_name FROM products WHERE stock_quantity > 0;","haridra@2003","maheshvanjre@yahoo.com", "SELECT COUNT(*) FROM products WHERE stock_quantity > 100;",
    "SELECT * FROM orders WHERE customer_id=5;", "SELECT department, COUNT(*) FROM employees WHERE hire_date > '2020-01-01' GROUP BY department;",
    "SELECT COUNT(*) FROM users WHERE status='active';", "SELECT DISTINCT city FROM customers WHERE country='France';",
    "SELECT name, department FROM employees WHERE department='Engineering';", "SELECT COUNT(*) FROM products WHERE price < 50;",
    "SELECT * FROM employees WHERE position='Manager';", "SELECT name, age FROM users WHERE registration_date > '2023-01-01';",
    "SELECT COUNT(*) FROM orders WHERE customer_id=4;", "UPDATE users SET status='inactive' WHERE id=12;",
    "SELECT * FROM products WHERE category='Books';", "SELECT MAX(total_price) FROM orders;",
    "SELECT id, product_name FROM products WHERE stock_quantity < 10;", "SELECT id, name, address FROM suppliers WHERE city='Berlin';",
    "SELECT name FROM products WHERE price BETWEEN 200 AND 500;", "SELECT COUNT(*) FROM sales WHERE region='Asia';",
    "INSERT INTO employees (name, department, salary) VALUES ('Alice', 'HR', 60000);", "SELECT * FROM users WHERE last_login > '2025-01-01';",
    "SELECT product_name, price FROM products WHERE stock_quantity > 0;", "SELECT COUNT(*) FROM employees WHERE position='Developer';",
    "SELECT * FROM customers WHERE registration_date BETWEEN '2025-01-01' AND '2025-12-31';",
    "SELECT MAX(price) FROM products WHERE category='Furniture';", "SELECT id, name FROM orders WHERE order_date > '2025-01-01';",
    "SELECT AVG(total_price) FROM orders WHERE status='Completed';", "SELECT * FROM sales WHERE product_id=7;",
    "SELECT COUNT(*) FROM suppliers WHERE country='China';", "SELECT name, email FROM customers WHERE email LIKE '%@yahoo.com';",
    "SELECT SUM(total_price) FROM orders WHERE order_date BETWEEN '2025-01-01' AND '2025-12-31';",
    "SELECT DISTINCT category FROM products WHERE price > 200;", "SELECT * FROM products WHERE name LIKE 'Laptop%';",
    "SELECT AVG(salary) FROM employees WHERE department='IT';", "SELECT * FROM customers WHERE country='Canada';",
    "SELECT id, name FROM employees WHERE department='Finance';","user@example.com", "john.doe@example.com", "alice.smith123@gmail.com",
    "mahmoud@2003", "bob@example.co.uk", "contact@domain.com", "charlie@domain.com",
    "alice@company.com", "user123@example.org", "michael@domain.com", "jane.doe@company.com", "SELECT id, name FROM products WHERE stock_quantity > 5;","SELECT * FROM users WHERE country='USA';","SELECT id, name FROM products WHERE price BETWEEN 50 AND 200;", "mahesh@2003","maheshvanjre@yahoo.com"
]

labels = [1]*111 + [0]*107  # Labels: 1 for SQLi, 0 for normal queries

# Create DataFrame
df = pd.DataFrame({'query': data, 'label': labels})

# Vectorize the data using TfidfVectorizer (Bag of Words model)
vectorizer = TfidfVectorizer(stop_words='english')  # Removing common English stop words
X = vectorizer.fit_transform(df['query'])

# Add additional features: special character count and email validation
X_additional = pd.DataFrame({
    'special_char_count': [count_special_characters(query) for query in df['query']],
    'is_email': [1 if is_email(query) else 0 for query in df['query']]
})

# Combine the original vectorized features with the new features
from scipy.sparse import hstack
X_combined = hstack([X, X_additional])

# Split the data into training and testing sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X_combined, df['label'], test_size=0.2, random_state=42)

# Initialize the Random Forest Classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the classifier
rf_classifier.fit(X_train, y_train)

# Save the model and vectorizer to files
joblib.dump(rf_classifier, 'sql_injection_classifier.pkl')
joblib.dump(vectorizer, 'sql_injection_vectorizer.pkl')

# Now, the model and vectorizer can be loaded for prediction later
# To load the model:
# rf_classifier = joblib.load('sql_injection_classifier.pkl')
# vectorizer = joblib.load('sql_injection_vectorizer.pkl')

# Make predictions
y_pred = rf_classifier.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy*100:.2f}%")
print("Classification Report:")
print(classification_report(y_test, y_pred))