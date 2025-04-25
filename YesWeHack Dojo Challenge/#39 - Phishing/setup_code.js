const punycode = require('punycode');
const ejs = require('ejs');
const path = require('path');
const fs = require('fs');
const vm = require('vm');
const sqlite3 = require('sqlite3').verbose();

// Change workdir
process.chdir('/tmp');

// Open a database connection
const db = new sqlite3.Database(':memory:');

// Add the flag as an enviroment variables
process.env.FLAG = flag;

// Write template file
fs.writeFileSync(`index.ejs`, `
<html>
<body>

<!-- Search box --> 
<div class="wrapper">
    <form>
        <div>
            <h1>Buy a website</h1>
        </div>
        <div class="icon">
            <img src="https://api.iconify.design/game-icons:shark-fin.svg?color=%23fff">
        </div>
        <input class="search" type="search" placeholder="Search..." value="<%= query.replaceAll(/<|>/g, '_') %>">
        <input class="btn" type="button" value="">
        <div class="options">
            <button>Blog</button>
            <button>Shop</button>
            <button>SaaS</button>
        </div>
        <h2>Buy a phishing website. Free fish included!</h2>
    </form>
</div>

<% if ( error ) { %>
    <div class="notify" style="background-color: rgba(201, 48, 48, 0.8);">
        <img src="https://api.iconify.design/game-icons:fishbone.svg?color=%23fff">
        <p><%= error %></p>
    </div>
<% } else if ( message ) { %>
    <div class="notify" style="background-color: rgba(124, 201, 48, 0.8);">
        <img src="https://api.iconify.design/mdi:fishbowl.svg?color=%23fff">
        <p><%= message %></p>
    </div>
<% } %>

<style>
@import url('https://fonts.googleapis.com/css2?family=Averia+Sans+Libre:ital,wght@0,300;0,400;0,700;1,300;1,400;1,700&family=Sour+Gummy:ital,wght@0,100..900;1,100..900&display=swap');

:root {
    --bg-color-btn-main: rgb(94, 155, 229);
    --txt-btn: #fff;
    --notify-icon: #d61515;
}

body {
    font-family: "Sour Gummy", sans-serif;
    font-optical-sizing: auto;
    font-weight: 400;
    font-style: normal;
    font-style: normal;
    background: linear-gradient(to top right, #1b2137, #4d5d90);
    background-image: url("https://static.vecteezy.com/ti/gratis-vektor/p1/16162429-under-vattnet-landskap-manta-och-haj-sjogras-vector.jpg");
    background-size: cover;
    display: flex;
    font-size: 16px;
    justify-content: center;
    align-items: center;
    color: #fff;
    height: 100vh;
    margin: 0;
    cursor: url("https://api.iconify.design/fluent:cursor-20-filled.svg?color=%23888888"), auto;
}

.ref {
    position: fixed;
    bottom: 0;
    right: 0;
    color: white;
    text-decoration: none;
}

.wrapper h1, h2, h3 {
    display: flex;
    justify-content: center;
    text-shadow: 0px 3px 7px rgb(0,0,0,0.5);
}
.wrapper input {
    letter-spacing: 0.125em;
    border-radius: 16px;
    font-size: 16px;
    background-color: #fff;
    padding-left: 12px;
    height: 60px;
}

.wrapper .icon {
    display: flex;
    justify-content: center;
    width: 60px;
    height: 60px;
    position: absolute;
    border-radius: 50%;
}

.wrapper .icon img {
    position: absolute;
    background-color: var(--bg-color-btn-main);
    border-radius: 50%;
    padding: 3px;
    transform: translate(-50%,-50%);
    left: 50%;
    top: 50%;
    width: 34;
    height: 34;
    border-top-left-radius: 36px;
    box-shadow: 1px 2px 8px rgb(0, 0, 0, 0.5);
    border: solid 2px white;
}

.wrapper .search {
    width: 440px;
    padding-left: 70px;
    border-radius: 36px;
    border: none;
    color: #323232;
}

.wrapper .btn {
    background-image: url("https://api.iconify.design/material-symbols:phishing-rounded.svg?color=%23888888");
    background-repeat: no-repeat;
    background-size: 34px;
    background-position: center;
    border: none;
    cursor: pointer;
    font-size: 16px;
    position: absolute;
    width: 60px;
    margin-left: 4px;
    height: 60px;
    font-weight: 600;
    border-radius: 33px;
    text-align: center;
    transition: 0.2s;
    border-bottom: solid 4px rgb(218, 218, 218);
}

.wrapper .btn:active {
    background-color: #ebebeb;
    box-shadow: 0 2px #363636;
    transform: translateY(3px);
}

.wrapper .options {
    padding-top: 20px;
    display: flex;
    justify-content: center;
    text-shadow: 0px 3px 7px rgb(0,0,0,0.5);
    gap: 40px;
}

.wrapper .options button {
    font-size: 16px;
    color: var(--txt-btn);
    border-radius: 36px;
    font-weight: 600;
    background-color: rgb(0,0,0,0.1);
    border: 2px solid var(--bg-color-btn-main);
    width: 100px;
    height: 40px;
    transition: 0.2s;
}

.wrapper .options button:hover {
    transform: translateY(3px);
}

.notify {
    display: flex;
    align-items: center;
    top: 20px;
    position: absolute;
    border-radius: 23px;
}

.notify p {
    margin-left: 20px;
    margin-right: 20px;
    font-size: 20px;
    font-weight: 600;
}

.notify img {
    margin: 10px;
    width: 42px;
    height: 42px;
}
</style>
</body>
</html>
`);

return {flag, secrets, punycode, db, ejs, fs, vm}