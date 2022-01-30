const express = require('express');
const http = require('http');
const socket = require('socket.io');
const app = express();
const cors = require('cors');
const server = http.createServer(app);
const Datastore = require('nedb');
const { instrument } = require('@socket.io/admin-ui');
const sha512 = require('crypto-js/sha512');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
let db = new Datastore();

/// create cron job everyday(1 day) for inactive 60 day deletion
const days = 1000 * 60 * 60 * 24 * 60; // 60 days in milliseconds

const io = socket(server, {
    cors: {
        origin: '*',
    }
});

// Use a VPN still!!
io.use((socket, next) => {
    socket.handshake.address = '';
    next();
});

instrument(io, {
    auth: false,
    readonly: true,
});

app.use(helmet());
app.use(cors());
app.use(express.json());

app.get('/', (_, res) => res.send('Server running...'));

app.get('/users', (_, res) => {
    db.find({}, (err, docs) => {
        if(err) console.log(err);
        res.send(docs);
    });
});

app.post('/createUser', (req, res) => { // make this more secure
    db.findOne({ _id: req.body.user }, (err, doc) => {
        if(err) console.log(err);
        if(doc === null) {
            db.insert({ 
                user: req.body.user,
                exp: new Date().getTime() + days,
                pass: sha512(req.body.pass).toString(), // argon
                socket: null,
            }, (err, _) => {
                if(err) console.log(err);
                res.sendStatus(200);
            });
        } else {
            res.sendStatus(500);
        }
    });
});

io.on('connection', (socket) => {
    
    socket.on('login', (data) => { // improve
        db.findOne({ user: data.user }, (err, doc) => {
            if(err) console.log(err);
            if(sha512(data?.pass).toString() === doc?.pass && doc?.socket) { // || cookie, jwt
                io.to(socket.id).emit('updateSocket', { socket: doc.socket });
                socket.disconnect();
            } else if(sha512(data?.pass).toString() === doc?.pass) {
                db.update({ user: data.user }, { $set: { socket: socket.id, exp: new Date().getTime() + days } }, {}, (err, _) => {
                    if(err) console.log(err);
                    io.to(socket.id).emit('updateSocket', { socket: socket.id });
                });
            } else {
                socket.disconnect();
            }
        });
    });

    socket.on('disconnect', () => {
        db.update({ socket: socket.id }, { $set: { socket: null } }, {}, (err, _) => {
            if(err) console.log(err);
        });
    });

    // Insecure, in person or other medium preferred, create X3 Diffie Hellman protocol
    socket.on('key_exchange', () => {

    });

    socket.on('sendRequest', (friend) => {
        db.findOne({ 
            _id: friend 
        }, (err, doc) => {
            if(err) console.log(err);
            if(doc !== null && doc?.socket) {
                console.log(doc);
                //io.to(socket).emit('recieveRequest', {  });
            }
        });
    });

    // not encrypted, on public chat
    socket.on('public-send', (data) => {
        const year = new Date().getUTCFullYear();
        const month = new Date().getUTCMonth() + 1;
        const day = new Date().getUTCDate();
        data['date'] = `${month}/${day}/${year} ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: true }).toLowerCase()} UTC`; 
        io.sockets.emit('public-retrieve', data);
    });

    socket.on('send message', ({ content, to, sender, chatName, isChannel }) => {
        if(isChannel) {
            const payload = {
                content,
                chatName,
                sender
            }
            socket.to(to).emit('new message', payload);
        } else {
            const payload = {
                content,
                chatName: sender,
                sender
            }
            socket.to(to).emit('new message', payload);
        }
    });
    
});

const port = 9000;
server.listen(port, () => console.log(`Server is running on port ${port}`));