async function main() {
    await Init_db();

    // User input
    var website = decodeURIComponent("");
    var sourcecode = decodeURIComponent("");

    if ( website.length == 0 ) {
        return {website, message:null}
    }

    try {
        // Check if website is available
        const isAvailable = await WebsiteIsAvailable(website)
        if ( !isAvailable ) {
            return {website, err:Error("This site has already been purchased by another user!")}
        }
        website = punycode.toUnicode(website)
        await BuyWebsite(website)

    } catch {
        return {website, err:Error("Invalid website given!")}
    }
    
    // Update the website for the client
    const websites = await GetAllWebsites()
    for ( let i = 0; i < websites.length; i++ ) {
        let wsite = websites[i].website
        if ( website == wsite ) {
            UpdateWebsiteContent(wsite, sourcecode)
            break
        }
    }

    // Verify the source code in a sandbox environment
    try {
        vm.runInContext(
            (await GetWebsiteCode("dójó-yeswehack.com")),
            vm.createContext({})
        );
    // Notify our infra in case we got an error
    } catch(err) {
        NotifyInfra(err)
        return {website, err:Error("Our code is broken!")}
    }

    return {website, message:"Nice catch - You're all set!"}
}
// Run the main application code
main().then((data) => {
    console.log( ejs.render(fs.readFileSync('index.ejs', 'utf8'), {
        query: data.website,
        message: data.message,
        error: (data.err) ? data.err.message : null
    }) )
})


// =====[Functions]===== //

async function Init_db() {
    return new Promise((resolve, reject) => {
        db.exec(`
            CREATE TABLE IF NOT EXISTS websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                code TEXT
            );
            INSERT INTO websites (website, code) VALUES
                ('dójó-yeswehack.com', '// Code in dev'),
                ('dojo-yeswehack.com', '// Code in dev')
        `, (err) => err ? reject(err) : resolve());
    });
}

async function WebsiteIsAvailable(website) {
    return new Promise((resolve, reject) => {
        const stmt = db.prepare(`SELECT website FROM websites WHERE website = ?`);
        stmt.all([website], 
            (err, rows) => err ? reject(err) : resolve( rows.length == 0 )
        );
    });
}

async function BuyWebsite(website) {
    return new Promise((resolve, reject) => {
        const stmt = db.prepare(`INSERT INTO websites(website) VALUES(?)`);
        stmt.run([website],
            (err) => err ? reject(err) : resolve()
        );
    });
}

async function UpdateWebsiteContent(website, code) {
    return new Promise((resolve, reject) => {
        const stmt = db.prepare(`UPDATE websites SET code = ? WHERE website = ?`);
        stmt.run([code, website],
            (err) => err ? reject(err) : resolve()
        );
    });
}

async function GetAllWebsites() {
    return new Promise((resolve, reject) => {
        db.all(`SELECT * FROM websites`, [], (err, rows) => {
            err ? reject(err) : resolve(rows)
        });
    });
}

async function GetWebsiteCode(website) {
     return new Promise((resolve, reject) => {
        const stmt = db.prepare(`SELECT code FROM websites WHERE website = ? LIMIT 1`);
        stmt.get([website], 
            (err, rows) => err ? reject(err) : resolve(rows.code)
        );
    });
}

function NotifyInfra(error) {
    return 'UmljayByb2xsZWQgYnkgaW5mcmE='
}