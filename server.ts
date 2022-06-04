import { ExtendedError } from "socket.io/dist/namespace";
import { Socket } from "socket.io/dist/socket";
import express, { Response, Request } from "express";
import { instrument } from '@socket.io/admin-ui';
import cryptojs from 'crypto-js';
import helmet from 'helmet';
import http from 'http';
import cors from 'cors';
import Datastore from 'nedb';
import { Server } from 'socket.io';
import { DateTime } from 'luxon';

const app = express();
const server = http.createServer(app);
const db = new Datastore();
const { SHA512: sha512 } = cryptojs;

/// create cron job everyday(1 day) for inactive 60 day deletion
const days = 1000 * 60 * 60 * 24 * 60; // 60 days in milliseconds

const io = new Server(server, {
  cors: {
    origin: "*",
  }
});

// Use a VPN still!!
io.use((socket: Socket, next: (err?: ExtendedError) => void) => {
  socket.handshake.address = '';
  next();
});

instrument(io, {
  auth: false,
  readonly: true,
  namespaceName: '/',
});

app.use(helmet());
app.use(cors());
app.use(express.json());

app.get('/', (_: Request, res: Response) => res.send('Server running...'));

app.get('/users', (_: Request, res: Response) => {
  db.find({}, (err: Error | null, docs: never[]) => {
    if(err) console.log(err);
    res.send(docs);
  });
});

app.post('/createUser', (req: Request, res: Response) => { // make this more secure
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
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  socket.on('key_exchange', () => {});

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
    const datetime = DateTime.utc().toISO();
    data['datetime'] = datetime;
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

export {}
