# [WEB] Baby Web
## Description
I just learnt how to design my favourite `flask` webpage using `htmx` and `bootstrap`. I hope I don't accidentally expose my super secret flag.

Author: Junhua

http://challs.nusgreyhats.org:33338

## Approach
By entering the link, we are greeted with the following landing page, which consists of an Admin navbar button and another button on the home page to request for admin access:
![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/a27baf47-32a8-46d1-8daf-b9ff696d1d8e)

Clicking on the "Request for admin access" button brings up a form but I doubt the form will be useful for solving the challenge.
![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/69f41f19-863a-4f15-b624-68d2204012b8)

Visiting the admin page tells us that we are not an admin, and thus we are unable to view the page contents.
![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/92c0c581-87b4-4878-8982-1ff6dd8217b3)

Usually when it comes to solving these web challenges, the ability to perform administratives stuff is determined by some sort of `is_admin` flag within our user token or session cookie. 
Opening up the browser devtools and navigating to the `Applications` tab allows us to view our cookies.
We see that there is indeed a session cookie stored within the browser.
> eyJpc19hZG1pbiI6ZmFsc2V9.ZiNCTw.nAkPamm6uC100yWSFfzDAXRSVz8

![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/5e72391f-79c9-4dd1-a27e-b77d80cf991f)

Knowing that the web application was created with flask, `wWe can use the tool `flask-unsign` to decrypt the session cookie.
> {'is_admin': False}

![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/2ce2e6de-06c0-4706-8a8e-c65fe17808d7)

Great! Now that we now that our `is_admin` flag is being stored in the session cookie with a value of `false`, we just need to create a new cookie with the flag set to `True`.
Once again, we can use `flask-unsign` to do this for us. But before that, we need to obtain the secret key used to sign the cookie. 
To do that, I tried to brute-force the secret key using rockyou.txt, however, that failed.
![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/2e3b70c2-2c55-45e1-a651-b52b56ec8dcb)

Then I remembered that the source code was already provided for us and the key could be hardcoded within.
![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/49bcd4e6-0c3f-477f-b7a1-0b29fa47d6a3)

Remember to study the source code provided next time guys :p

Using the secret key, we sign our new cookie.
> eyJpc19hZG1pbiI6dHJ1ZX0.ZiM_4g.YzRHfLlJ5GHGLbax4UVz56pdGzo

![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/29707f44-7205-41df-a7fa-8256bd888e23)

Replace our new cookie value into the "Value" field of the "session" cookie in our Browser's devtools and enter the admin page again.
This time, the content of the webpage appears different.
![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/138fef87-f5b3-4691-a7f5-685926c4db07)

It appears that we have reached a dead end, but inspecting the page's source code reveals that there is a hidden button:
![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/bd787a61-2c73-4ace-b46f-157e8324515d)

We just need to remove the hidden attribute on the button and click it, revealing the flag:
![image](https://github.com/0necloud/CTF-Writeups/assets/60743000/c7eeac63-ba39-477f-871a-ce6a98645382)

Flag: `grey{0h_n0_mY_5up3r_53cr3t_4dmin_fl4g}`



