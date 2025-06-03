require 'fileutils'
require 'securerandom'

Dir.chdir("/tmp")
# Write flag script file with execute only
filenameflag = "flag_#{SecureRandom.hex(10)}.txt"
File.write(filenameflag, flag)

# Make web app folder structure and add files
FileUtils.mkdir_p '/tmp/app/views'
Dir.chdir("/tmp/app/views")

# Write the login page
File.write("login.erb", '
<div class="login">
    <div class="input-group flex-nowrap">
        <img class="input-group-text" id="addon-wrapping"
            src="https://api.iconify.design/ic:round-email.svg?color=%23000">
        <input type="text" class="form-control" placeholder="Email" aria-label="Username / Email"
            aria-describedby="addon-wrapping">
    </div>
    <div class="input-group flex-nowrap">
        <img class="input-group-text" id="addon-wrapping"
            src="https://api.iconify.design/material-symbols:key-vertical-rounded.svg?color=%23000">
        <input type="password" class="form-control" placeholder="Password" aria-label="Password"
            aria-describedby="addon-wrapping">
    </div>
    <div class="d-grid gap-2 col-6 mx-auto">
        <button class="btn btn-danger" type="button">Login</button>
    </div>
</div>
')

# Write the collection page
File.write("collection.erb", '
<div class="collection">
    <div class="card">
        <img src="https://static.vecteezy.com/system/resources/previews/043/672/403/non_2x/expensive-diamonds-necklace-isolated-on-transparent-background-free-png.png"
            class="card-img-top">
        <div class="card-body">
            <h5 class="card-title">Necklace</h5>
            <p class="card-text">Necklace to flex from all angels</p>
            <a href="#" class="btn mt-auto">Buy for $42,000</a>
        </div>
    </div>

    <div class="card">
        <img src="https://static.vecteezy.com/system/resources/previews/050/038/385/non_2x/ruby-ring-with-diamonds-isolated-on-transparent-background-free-png.png"
            class="card-img-top">
        <div class="card-body">
            <h5 class="card-title">Bracelet</h5>
            <p class="card-text">An expensive Ruby ring</p>
            <a href="#" class="btn mt-auto">Buy for $31,337</a>
        </div>
    </div>
</div>
')

# Write the core template file
File.write("index.erb", '
<!DOCTYPE html>
<html>

<head>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script>
    <link rel="stylesheet" href="styles.css">
</head>

<body>
    <div>
        <nav class="navbar navbar-expand-lg bg-body-tertiary">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">
                    <img src="https://static.vecteezy.com/system/resources/previews/053/066/814/non_2x/free-logo-ruby-free-png.png"
                        width="34" height="auto">
                </a>
                <h4>Ruby Treasure</h4>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse"
                    data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent"
                    aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarSupportedContent">
                    <ul class="navbar-nav ms-auto">
                        <li class="nav-item">
                            <img src="https://api.iconify.design/material-symbols:home-rounded.svg?color=%23424242">
                            <a class="nav-link" href="#">Home</a>
                        </li>
                        <li class="nav-item">
                            <img src="https://api.iconify.design/material-symbols:lists-rounded.svg?color=%23424242">
                            <a class="nav-link" href="#">Collection</a>
                        </li>
                        <li class="nav-item">
                            <img src="https://api.iconify.design/material-symbols:login-rounded.svg?color=%23424242">
                            <a class="nav-link" href="#">Login</a>
                        </li>
                    </ul>
                </div>
            </div>

        </nav>
        <!-- current page -->
        <%= page %>
</body>
<style>
@import url("https://fonts.googleapis.com/css2?family=Averia+Sans+Libre:ital,wght@0,300;0,400;0,700;1,300;1,400;1,700&family=Changa:wght@200..800&family=Coiny&family=Finger+Paint&family=Jersey+15&family=Knewave&family=Schoolbell&family=Sour+Gummy:ital,wght@0,100..900;1,100..900&display=swap");

:root {
    --color-main: #fff;
    --color-txt: #fff;
    --color-red: #ec1521;
}

body {
    color: var(--color-txt);
    font-family: "Averia Sans Libre", sans-serif;
    font-weight: 400;
    font-style: normal;
    position: relative;
    align-items: center;
    background-color: #000;
    background-image: url("https://static.vecteezy.com/ti/gratis-foton/p1/53857795-rod-och-vit-bakgrund-med-en-rod-och-vit-flamma-de-bakgrund-ar-fylld-med-rok-och-de-flamma-ar-stor-och-ljus-de-rok-ar-virvlande-och-de-flamma-ar-dans-gratis-fotona.jpg");
    background-size: cover;
    height: 100vh;
    margin: 0;
    padding: 0;
}
h4 {
    color: var(--color-red);
}
/* General */
.btn {
    color: var(--color-txt);
    background-color: var(--color-red);
    border: none;
    font-size: 18px;
    font-weight: 900;
    transition: transform .3s;
    border: 1px solid var(--color-main)
}

.btn:hover {
    background-color: var(--color-red);
}

.btn:active {
    background-color: var(--color-red);
}

/* Navbar */
.nav-item {
    display: flex;
    font-size: 22px;
}

.nav-item img {
    padding: 2px;
    width: 32px;
    height: auto;
}

.nav-link {
    transition: transform 0.3s;
}

.nav-link:hover {
    color: var(--color-red)
}

/* page - Collection */
.collection {
    display: flex;
    justify-content: center;
    align-items: center;
    width: 100%;
}

.cards {
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
}

.card {
    cursor: pointer;
    background-color: var(--color-main);
    border-radius: 12px;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
    width: 340px;
    height: 480px;
    margin: 1rem;
    text-align: center;
    transition: transform 0.3s;
}

.card .title {
    font-size: 22px;
}

.card a {
    position: absolute;
    transform: translate(-50%, -50%);
    width: 200px;
    bottom: 0;
}

.card p {
    font-size: 18px;
}

.card img {
    width: 100%;
    height: auto;
    background-size: cover;
}

.card:hover {
    transform: scale(1.02);
}

/* page - Login */
.login {
    display: grid;
    padding: 20px;
    gap: 4vh;
    justify-content: center;
    align-items: center;
}
</style>
</html>
')
