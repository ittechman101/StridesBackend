//Middleware to add to any routes to only allow authenticated users to access them

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Password = require('../models').Password;

const authMiddleware = async (req, res, next)=>{
    //Pull the token value from the header on any requests that come in. If the token isn't present, reject access to the route
    const token = req.header('Authorization');
    if(!token) res.status(401).send("Access Denied");

    try{
        var pwExist = false;
        const allPasswords = await Password.findAll();
        for (let i = 0; i < allPasswords.length; i++)  {
            const exist = await bcrypt.compare(token, allPasswords[i].hash);
            if(exist) { 
                pwExist = true; 
                break; 
            }
        }

        if(pwExist) { req.header.Authorization = token; }
        else { req.header.Authorization = null; }
        next();
    }catch(e){
        res.status(401).send("Access Denied");
    }

    
}

module.exports = authMiddleware;