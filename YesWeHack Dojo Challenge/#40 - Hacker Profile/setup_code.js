const ejs = require("ejs")
const fs = require("fs")
process.chdir('/tmp')

// Add flag as a system enviroment variable
process.env.FLAG = flag

var profiles = [
    {
        "picture": "https://static.vecteezy.com/ti/gratis-vektor/p1/9521808-vintage-eleganta-lejonkungen-krona-illustrationer-vector.jpg",
        "username": "minilucker",
        "isActive": true,
        "description": "a zero-click 0-day is an error that is so violent that you have 0 days to patch it",
        "lastViewed": Date(),
        "impact": 35,
        "points": 1337,
        "bugCount": 102,
    },
    {
        "picture": "https://static.vecteezy.com/ti/gratis-vektor/p1/49009497-sot-socker-segelflygplan-tecknad-serie-illustration-vector.jpg",
        "username": "pwnwithlove",
        "isActive": true,
        "description": "i <3 sugar gliders",
        "lastViewed": Date(),
        "impact": 34,
        "points": 4212,
        "bugCount": 431,
    },
    {
        "picture": "https://static.vecteezy.com/ti/gratis-vektor/p2/47321447-elefant-hog-kvalitet-logotyp-illustration-idealisk-for-t-shirt-grafisk-vector.jpg",
        "username": "BitK",
        "isActive": true,
        "description": "Babar Is The King",
        "lastViewed": Date(),
        "impact": 40,
        "points": 1352,
        "bugCount": 125,
    },
    {
        "picture": "https://static.vecteezy.com/ti/gratis-vektor/p1/24681876-varg-ansikte-logotyp-vektor-illustration-vector.jpg",
        "username": "Brumens",
        "isActive": true,
        "description": "Your beloved Dojo chall maker",
        "lastViewed": Date(),
        "impact": 29,
        "points": 2245,
        "bugCount": 212,
    }
]

// Write the ejs template file
fs.writeFileSync('index.ejs', `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
</head>    
<body>
    <div class="wrapper">
        <div class="profile-wrapper">
        <% if (error === undefined) { %>
            <div class="profile">
                <img class="icon" src="https://api.iconify.design/basil:upload-solid.svg?color=%23fff">
                <img  class="pic" src="<%= user.picture %>">
                <img class="icon" src="https://api.iconify.design/material-symbols:edit-document.svg?color=%23fff">
            </div>
            <div class="info">
                <div class="field">
                    <div>
                        <img src="https://api.iconify.design/material-symbols-light:swords-rounded.svg?color=%23fff">
                        <b>Impact</b>
                    </div>
                    <p><%= user.impact %></p>
                </div>
                <div class="field">
                    <div>
                        <img src="https://api.iconify.design/bx:stats.svg?color=%23fff">
                        <b>Points</b>
                    </div>
                    <p><%= user.points %></p>
                </div>
                <div class="field">
                    <div>
                        <img src="https://api.iconify.design/solar:bug-bold.svg?color=%23fff">
                        <b>Bugs</b>
                    </div>
                    <p><%= user.bugCount %></p>
                </div>
            </div>

            <div class="field-text">
                <span class="field-key">Username:</span>
                <span class="field-value"><%= user.username %></span>
            </div>
            <div class="field-text">
                <span class="field-key">IsActive:</span>
                <span class="field-value"><%= user.isActive %></span>
            </div>
            <div class="field-text">
                <span class="field-key">Description:</span>
                <span class="field-value"><%= user.description %></span>
            </div>
            <div class="field-text">
                <span class="field-key">Viewed:</span>
                <span class="field-value"><%= user.lastViewed %></span>
            </div>
        <% } else { %>
            <pre id="errorDisplay"><%= error %></pre>
            <% if (logs !== undefined) { %> 
                <hr>
                    <pre id="debugLogs">
                        <%= logs %>
                    </pre>
                <hr>
            <% } %>
        <% } %>
        </div>
    </div>
<style>
@import url('https://fonts.googleapis.com/css2?family=Averia+Sans+Libre:ital,wght@0,300;0,400;0,700;1,300;1,400;1,700&family=Changa:wght@200..800&family=Coiny&family=Finger+Paint&family=Jersey+15&family=Knewave&family=Schoolbell&family=Sour+Gummy:ital,wght@0,100..900;1,100..900&display=swap');

:root {
    --color-txt: white;
    --color-bg: #101e11;
    --color-border: #4a4a4a;
    --color-bg-info-field: #f66158;
    --color-bg-profile: #273036;
    --color-bg-field-text: #273036;
}

body {
    background-image: url("https://static.vecteezy.com/ti/gratis-vektor/p1/45711034-monster-med-kvadrater-digital-bla-teknologi-bakgrund-vector.jpg"); // We have licensed account for this
    background-size: cover;
    font-family: "Coiny", serif;
    font-weight: 400;
    font-style: normal;
    background-color: var(--color-bg);
    background-size: cover;
    padding: 0;
    margin: 0;
    color: var(--color-txt);
    font-size: 18px;
}

.wrapper {
    position: fixed;
    display: flex; 
    flex-direction: column; 
    justify-content: space-between; 
    align-items: stretch; 
    border-radius: 25px;
    padding: 20px;
    transform: translate(-50%, -50%);
    top: 50%;
    left: 50%;
}

/* Profile container */
.profile-wrapper {
    background-color: var(--color-bg-profile);
    border: 1px solid var(--color-border);
    border-radius: 22px;
    padding: 30px;
    width: 300px;
    box-shadow: 0 0 20px rgba(0, 0, 0, 0.3);
    
}
.profile-wrapper .profile {
    display: flex;
    align-items: center;
}

.profile-wrapper .profile .icon {
    width: 32px;
    height: 32px;
    cursor: pointer;
}

/* Profile picture */
.profile-wrapper .profile .pic {
    width: 110px;
    height: 110px;
    border-radius: 50%;
    margin: 0 auto 20px;
    display: block;
    border: 2px solid var(--color-border);
    object-fit: cover;
}

/* Info fields */
.info {
    padding: 0;
    margin: 0;
    display: inline-flex;
    gap: 12px;
    padding-bottom: 14px;
}
.info .field {
    padding: 6px;
    background-color: var(--color-bg-info-field);
    border-radius: 13px;
    display: grid;
    justify-content: center;
    align-items: center;
    width: 80px;
    height: 50px;
    transition: 0.33s;
    font-size: 14px;
}
.info .field div {
    display: flex;
    gap: 4px;
}
.info .field img {
    width: 24px;
    height: 24px;
}
.info .field p {
    margin: 0;
}
.field:hover {
    cursor: pointer;    
    transform: translate(0, -8px);
}

/* Text field */
.field-text {
    display: flex;
    justify-content: space-between;
    background-color: var(--color-bg-field-text);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    color: #e0e0e0;
    font-size: 16px;
    margin-bottom: 15px;
    padding: 10px;
    transition: background-color 0.3s ease;
}

.field-text:hover {
    background-color: #404040;
}

/* Key (left part) */
.field-key {
    font-weight: bold;
    color: #8a8a8a;
}

/* Value (right part) */
.field-value {
    text-align: right;
    flex-grow: 1;
    margin-left: 10px;
}

/* Editable style for the value */
.field-value[contenteditable="true"]:focus {
    outline: none;
    border-bottom: 1px dashed #6a6a6a;
}

#errorDisplay {
    background-color: #ff4444;
    color: white;
    padding: 10px;
    margin-bottom: 20px;
    border-radius: 5px;
}

#debugLogs {
    background-color: #2a2a2a;
    border: 1px solid var(--color-border);
    border-radius: 5px;
    overflow: auto;
    max-height: 400px;
}

pre {
    margin: 0;
    padding: 10px;
    white-space: pre-wrap;
    word-wrap: break-word;
    line-height: 1.5;
}

.log-entry {
    margin-bottom: 5px;
    border-bottom: 1px solid #3a3a3a;
    padding-bottom: 5px;
}
    </style>
</body>
</html>
`)

return {fs, ejs, profiles}