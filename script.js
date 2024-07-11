function countWords(inputText) {
            // Trim leading and trailing white spaces
            inputText = inputText.trim();
            
            // Split the input text into words
            let words = inputText.split(/\s+/);
            
            // Get current word count
            let wordCount = words.length;
            
            // Display remaining words
            let remaining = 180 - wordCount;
            document.querySelector(".wordsRemaining").textContent = remaining;
            
            // Limit text length to 180 words
            if (wordCount > 180) {
                // Split the words array and join the first 180 words
                words = words.slice(0, 180);
                document.querySelector(".textInput").value = words.join(" ");
                document.querySelector(".wordsRemaining").textContent = 0;
            }
        }