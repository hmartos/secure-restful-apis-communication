const fs = require('fs');
const path = require('path');

function readFileAsString(filePath) {
    try {
        // Resolve the absolute path for the file
        const absolutePath = path.resolve(filePath);

        // Read the file content as a string (utf-8 encoding)
        const fileContent = fs.readFileSync(absolutePath, 'utf8');

        return fileContent;
    } catch (error) {
        // Handle common errors, such as file not found, permission issues, etc.
        if (error.code === 'ENOENT') {
            console.error(`File not found: ${filePath}`);
        } else if (error.code === 'EACCES') {
            console.error(`Permission denied: ${filePath}`);
        } else {
            console.error(`An error occurred while reading the file: ${error.message}`);
        }
        return null;  // Return null to signify failure in reading the file
    }
}

module.exports = { readFileAsString };
