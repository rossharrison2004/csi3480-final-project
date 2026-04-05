//Gets user input from UI and calls generate() to create a password
function generatePassword() {
    const length = parseInt(document.getElementById('length').value);
    const includeUppercase = document.getElementById('upper').checked;
    const includeLowercase = document.getElementById('lower').checked;
    const includeNumbers = document.getElementById('digits').checked;
    const includeSymbols = document.getElementById('symbols').checked;

    document.getElementById('generatedPassword').innerText = generate(length, includeUppercase, includeLowercase, includeNumbers, includeSymbols);
}

//Builds a character set based on user selection and returns a randomly generated password of the specified length
function generate(length, includeUppercase, includeLowercase, includeNumbers, includeSymbols) {
    const uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
    const numberChars = '0123456789';
    const symbolChars = '!@#$%^&*()_+-=~`|{}[]:;?><,./';

    let characters = '';

    if (includeUppercase) characters += uppercaseChars;
    if (includeLowercase) characters += lowercaseChars;
    if (includeNumbers) characters += numberChars;
    if (includeSymbols) characters += symbolChars;  

    if (characters.length === 0) {
        alert('Please select at least one character type!');
        return '';
    }

    let password = '';  
    for (let i = 0; i < length; i++) {
        password += characters.charAt(Math.floor(Math.random() * characters.length));
    }   

    return password;
}

//Copies the generated password to the clipboard
function copyText(id) {
    const text = document.getElementById(id).innerText;

    navigator.clipboard.writeText(text).then(() => {
        alert('Password copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}

//Toggles the visibility of the password and hash
function toggleVisibility(inputId, button) {
    const input = document.getElementById(inputId);

    if (input.type === 'password') {
        input.type = 'text';
        button.textContent = 'Hide';
    } else {
        input.type = 'password';
        button.textContent = 'Show';
    }
}