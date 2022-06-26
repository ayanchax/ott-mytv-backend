
var request = require("request");
const jwt = require('jsonwebtoken');
var token = "";
const SECRET_KEY = "$2a$10$8p7PaLxyJNYSj06987dvSOzjqNtJhQ6JzYjWtBJb4FRfCQ6Vy.3zW"; //Adding secret key for JWT authentication
const SERVER_URL = process.env.DAS_BACKEND_HOST || "http://localhost:3000";

describe("Simple REST API", function () {
    beforeAll(function () {
        jwt.sign({email: "johndoe@gmail.com"}, SECRET_KEY, (err, data) => {
            if (err) throw err;
            token = data;
        })
    })

    it("should receive user details", function (done) {
        request.get(SERVER_URL + "/users", { 'auth': { 'bearer': token } }, function (error, response) {
            expect(response.statusCode).toBe(200);
            expect(response).not.toBeNull();
            expect('Content-Type', 'json')
            done();
        })
    })

    it("should return 401 unauthorized access", function (done) {
        request.get(SERVER_URL + "/users", function (error, response) {
            expect(response.statusCode).toBe(401);
            done();
        })
    })

   
    it("should receive user details", function (done) {
        request.get(SERVER_URL + "/users/37c16230-ac90-11ea-8562-4353b1ef4e91", function (error, response) {
            expect(response.statusCode).toBe(200);
            expect(response).not.toBeNull();
            expect('Content-Type', 'json')
            done();
        })
    })

 
    it("should receive terms of service", function (done) {
        request.get(SERVER_URL + "/tos/94202640-5494-11eb-bc5f-090e493b644c", function (error, response) {
            expect(response.statusCode).toBe(200);
            expect(response).not.toBeNull();
            expect('Content-Type', 'json')
            done();
        })
    })

    

    it("should receive logged in status", function (done) {
        request.get(SERVER_URL + "/loggedInStatus", { 'auth': { 'bearer': token } }, function (error, response) {
            expect(response.statusCode).toBe(200);
            expect(response).not.toBeNull();
            expect('Content-Type', 'json')
            done();
        })
    })

    it("should return 401 unauthorized access", function (done) {
        request.get(SERVER_URL + "/loggedInStatus", function (error, response) {
            expect(response.statusCode).toBe(401);
            done();
        })
    })
    
    it("should receive privacy policy", function (done) {
        request.get(SERVER_URL + "/privacy/94202640-5494-11eb-bc5f-090e493b644c", function (error, response) {
            expect(response.statusCode).toBe(200);
            expect(response).not.toBeNull();
            expect('Content-Type', 'json')
            done();
        })
    })
    
    it("should receive latest terms of services", function (done) {
        request.get(SERVER_URL + "/tos/latest/94202640-5494-11eb-bc5f-090e493b644c", function (error, response) {
            expect(response.statusCode).toBe(200);
            expect(response).not.toBeNull();
            expect('Content-Type', 'json')
            done();
        })
    })

    
    it("should receive latest privacy policy", function (done) {
        request.get(SERVER_URL + "/privacy/latest/94202640-5494-11eb-bc5f-090e493b644c", function (error, response) {
            expect(response.statusCode).toBe(200);
            expect(response).not.toBeNull();
            expect('Content-Type', 'json')
            done();
        })
    })

   
    it("should receive customer details", function (done) {
        request.get(SERVER_URL + "/customers", function (error, response) {
            expect(response.statusCode).toBe(200);
            expect(response).not.toBeNull();
            expect('Content-Type', 'json')
            done();
        })
    })


})




   