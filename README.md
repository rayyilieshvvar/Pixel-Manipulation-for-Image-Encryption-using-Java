# Pixel Manipulation for Image Encryption using Java

A simple tool using pixel manipulation to encrypt and decrypt images. This tool allows users to perform operations like swapping pixel values or applying basic mathematical operations to each pixel.

## Project Overview

This project provides a Java-based image encryption tool that uses pixel manipulation to encrypt and decrypt images. The tool uses the AES encryption algorithm with a 128-bit key and CBC mode with PKCS5 padding. The encryption and decryption processes involve reading and writing image files, generating and storing encryption keys and initialization vectors, and performing the actual encryption and decryption operations.

## File Hierarchy

- **ImageEncryptionTool.java**: The main Java class that implements the image encryption and decryption functionality.
- **key.bin**: The file that stores the encryption key.
- **iv.bin**: The file that stores the initialization vector.
- **encrypted_images/**: The directory that stores the encrypted image files.
- **decrypted_images/**: The directory that stores the decrypted image files.

## Installation and Setup

### Prerequisites

- Java Development Kit (JDK) 8 or later
- Eclipse or any other Java IDE

### Steps to Install and Set Up

1. Install the Java Development Kit (JDK) 8 or later on your system.
2. Install Eclipse or any other Java IDE.
3. Create a new Java project in Eclipse and add the `ImageEncryptionTool.java` file to the project.
4. Create the `encrypted_images/` and `decrypted_images/` directories in the project root.
5. Compile and run the `ImageEncryptionTool.java` file.

## Usage

This project can be used to encrypt and decrypt images for secure storage or transmission. The encryption key and initialization vector are stored in separate files, which can be used to decrypt the image later.

## Compilation and Execution

### Compile the Java File

1. Open a terminal.
2. Navigate to the directory where your `ImageEncryptionTool.java` file is located.
3. Compile the Java file using the following command:

    ```sh
    javac ImageEncryptionTool.java
    ```

    This will create a new `ImageEncryptionTool.class` file in the same directory.

### Run the Java Program

1. To run the Java program, use the following command:

    ```sh
    java ImageEncryptionTool
    ```

    This will execute the `ImageEncryptionTool` program, and you will be prompted to enter the operation (either 'E' for encryption or 'D' for decryption) and the file path.

## Example Usage

### Encrypting an Image

1. Run the program:

    ```sh
    $ java ImageEncryptionTool
    ```
2. When prompted, enter 'E' to encrypt:

    ```
    Enter 'E' to encrypt or 'D' to decrypt: E
    ```
3. Enter the file path of the image you want to encrypt:

    ```
    Enter the file path: /path/to/image.jpg
    ```

    This will encrypt the image file located at `/path/to/image.jpg` and store the encrypted file in the `encrypted_images/` directory.

### Decrypting an Image

1. Run the program:

    ```sh
    $ java ImageEncryptionTool
    ```
2. When prompted, enter 'D' to decrypt:

    ```
    Enter 'E' to encrypt or 'D' to decrypt: D
    ```
3. Enter the file path of the encrypted image you want to decrypt:

    ```
    Enter the file path: /path/to/encrypted_image.jpg
    ```

    This will decrypt the encrypted image file located at `/path/to/encrypted_image.jpg` and store the decrypted file in the `decrypted_images/` directory.

## Directory Structure

- `ImageEncryptionTool.java` - Java source file.
- `ImageEncryptionTool.class` - Compiled Java class file (generated after compilation).
- `encrypted_images/` - Directory where encrypted images are stored.
- `decrypted_images/` - Directory where decrypted images are stored.
