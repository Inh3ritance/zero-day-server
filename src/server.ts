import { ExtendedError } from 'socket.io/dist/namespace';
import { Socket } from 'socket.io/dist/socket';
import express, { Response, Request } from 'express';
import { instrument } from '@socket.io/admin-ui';
import argon2 from 'argon2';
import helmet from 'helmet';
import http from 'http';
import cors from 'cors';
import Datastore from 'nedb';
import { Server } from 'socket.io';
import { DateTime } from 'luxon';
import { SOCKET_EVENTS } from './constants';

const app = express();
const server = http.createServer(app);
const db = new Datastore();

/// create cron job everyday(1 day) for inactive 60 day deletion
const days = 1000 * 60 * 60 * 24 * 60; // 60 days in milliseconds

const io = new Server(server, {
  cors: {
    origin: '*',
  },
});

// Use a VPN still!!
io.use((socketParam: Socket, next: (err?: ExtendedError) => void) => {
  const socket = socketParam;
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
    if (err) console.error(err);
    res.send(docs);
  });
});

app.post('/createUser', async (req: Request, res: Response) => { // make this more secure
  db.findOne({ _id: req.body.user }, async (err, doc) => {
    if (err) console.error(err);
    if (doc === null) {
      db.insert({
        user: req.body.user,
        exp: new Date().getTime() + days,
        pass: await argon2.hash(req.body.pass),
        socket: null,
      }, (error, _) => {
        if (error) console.error(error);
        res.sendStatus(200);
      });
    } else {
      res.sendStatus(500);
    }
  });
});

io.on(SOCKET_EVENTS.CONNECTION, (socket) => {
  socket.on(SOCKET_EVENTS.LOGIN, (data) => { // improve
    db.findOne({ user: data.user }, async (err, doc) => {
      if (err) console.error(err);
      if (await argon2.verify(doc?.pass, data?.pass)) {
        console.log(doc);
        if (doc?.socket) {
          io.to(socket.id).emit(SOCKET_EVENTS.UPDATE_SOCKET, { socket: doc.socket });
        } else {
          // Set a socket to a user if none exists in the DB for that user
          // TODO - Fix socket not getting set correctly in update
          db.update({ user: data.user }, { $set: { socket: socket.id, exp: new Date().getTime() + days } }, {}, (error, _) => {
            if (error) console.error(error);
            io.to(socket.id).emit(SOCKET_EVENTS.UPDATE_SOCKET, { socket: socket.id });
          });
        }
      } else {
        socket.disconnect();
      }
    });
  });

  socket.on(SOCKET_EVENTS.DISCONNECT, () => {
    db.update({ socket: socket.id }, { $set: { socket: null } }, {}, (err, _) => {
      if (err) console.error(err);
    });
  });

  // Insecure, in person or other medium preferred, create X3 Diffie Hellman protocol
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  socket.on('key-exchange', () => {});

  socket.on(SOCKET_EVENTS.SEND_REQUEST, (friend) => {
    db.findOne({
      _id: friend,
    }, (err, doc) => {
      if (err) console.log(err);
      if (doc !== null && doc?.socket) {
        console.log(doc);
        // io.to(socket).emit('recieveRequest', {  });
      }
    });
  });

  // not encrypted, on public chat
  socket.on(SOCKET_EVENTS.PUBLIC_SEND, (dataParam) => {
    const data = dataParam;
    const datetime = DateTime.utc().toISO();
    data.datetime = datetime;
    io.sockets.emit(SOCKET_EVENTS.PUBLIC_RETRIEVE, data);
  });

  socket.on(SOCKET_EVENTS.SEND_MESSAGE, ({
    content, to, sender, chatName, isChannel,
  }) => {
    if (isChannel) {
      const payload = {
        content,
        chatName,
        sender,
      };
      socket.to(to).emit(SOCKET_EVENTS.NEW_MESSAGE, payload);
    } else {
      const payload = {
        content,
        chatName: sender,
        sender,
      };
      socket.to(to).emit(SOCKET_EVENTS.NEW_MESSAGE, payload);
    }
  });
});

const port = 9000;
server.listen(port, () => console.log(`Server is running on port ${port}`));

export {};
