const DEBUG_MODE = process.env.DEBUG_MODE;

// Function to show debug messages by console
function debug(message, params) {
  if(DEBUG_MODE) {
    params ? console.log(message, params) : console.log(message);
  }
}

module.exports = { debug };