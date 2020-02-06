const request = require("request");


function checkUsername(username) {
    return new Promise((resolve, reject) => {
        request("https://api.mojang.com/users/profiles/minecraft/" + username, function (err, res, body) {
            if (err||res.status === 204) {
                reject();
                return;
            }
            try {
                let json = JSON.parse(body);
                resolve(json["id"]);
            } catch (e){
                reject(e);
            }
        })
    })
}

function base64encode(string) {
    return Buffer.from(string).toString("base64");
}

function base64decode(string) {
    return Buffer.from(string, "base64").toString("utf8");
}

module.exports = {checkUsername,base64encode,base64decode};
