process.chdir('/tmp');
// Define the app config
appConfig = {
    title: "Hacker Profile",
    author: "Minilucker"
}

// Return a random hacker profile
function getRandomProfile(profiles) {
    return profiles[Math.floor(Math.random() * profiles.length)];
}

// Set the user properties
function setUserProperties(target, source) {
    for (let key of Object.keys(source)) {
        typeof target[key] !== "undefined" && typeof source[key] === "object" ?
            target[key] = setUserProperties(target[key], source[key]) :
            target[key] = source[key];
    }
    return target
}

// Take user profile properties
var profile = decodeURIComponent("")
if ( profile.length == 0 ) {
    profile = "{}"
}
profile = JSON.parse(profile)

const defaultUser = getRandomProfile(profiles)
const user = setUserProperties(defaultUser, profile)

try {
    Object.keys(user).forEach((key) => {
        if (key === "lastViewed") {
            user[key] = user[key].toLocaleString().split('GMT')[0]
        } else {
            user[key] = user[key].toString()
        }
    })
    console.log(ejs.render(fs.readFileSync('index.ejs', "utf-8"), { user, error: undefined, logs: "" }))
    
} catch (error) {
    if (appConfig.debug && appConfig.debug.active === true) {
        const logs = eval(`${appConfig.debug.code}`)
        console.log(ejs.render(fs.readFileSync('index.ejs', "utf-8"), { user: undefined, error, logs }))
    }
    else {
        console.log(ejs.render(fs.readFileSync('index.ejs', 'utf-8'), { error, user:undefined, logs: undefined }))
    }
}
