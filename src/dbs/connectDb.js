'use strict'

const mongoose = require('mongoose');

const {db} = require('../configs/config.js');


const url = `mongodb://localhost:27017/test`


class Database {

    constructor(){
        this.connect();
    }

    connect(type = 'mongodb'){
        mongoose.connect(url).then( () => console.log(`Mongodb Success Port::${url} !!!`))
            .catch( err => console.log(err));
    }
    static getInstance(){
        if(!Database.instance){
            Database.instance = new Database();
        }
        return Database.instance;
    }
}

const instanceMongodb = Database.getInstance();

module.exports = instanceMongodb;