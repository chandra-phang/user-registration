/**
  This is the SQL script that will be used to initialize the database schema.
  We will evaluate you based on how well you design your database.
  1. How you design the tables.
  2. How you choose the data types and keys.
  3. How you name the fields.
  In this assignment we will use PostgreSQL as the database.
  */

CREATE TABLE users (
  "id" varchar(36) PRIMARY KEY,
  "phone_number" varchar(15) UNIQUE NOT NULL,
  "name" varchar(60) NOT NULL,
  "password" text NOT NULL,
  "created_at" TIMESTAMP(0) NOT NULL,
  "updated_at" TIMESTAMP(0) NOT NULL
);

CREATE INDEX idx_users_on_phone_number ON users("phone_number");
