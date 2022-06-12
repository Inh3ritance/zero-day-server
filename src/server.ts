import { ExtendedError } from 'socket.io/dist/namespace';
import { Socket } from 'socket.io/dist/socket';
import express, { Response, Request } from 'express';
import { instrument } from '@socket.io/admin-ui';
import argon2 from 'argon2';
import helmet from 'helmet';
import http from 'http';
import cors from 'cors';
import { PrismaClient } from '@prisma/client'
import { Server } from 'socket.io';
import { DateTime } from 'luxon';
import { SOCKET_EVENTS } from './constants';

const app = express();
const server = http.createServer(app);
const prisma = new PrismaClient();
const PORT = 9000;

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

app.post('/createUser', async (req: Request, res: Response) => {
  try {
    const user = await prisma.user.findFirst({
      where: {
        user: String(req.body.user),
      },
    });
    if (!user) {
      await prisma.user.create({
        data: {
          user: req.body.user,
          exp: new Date().getTime() + days,
          pass: await argon2.hash(req.body.pass),
        }
      });
    }
    res.sendStatus(200);
  } catch (e) {
    console.log(e);
    res.sendStatus(500);
  }
});

io.on(SOCKET_EVENTS.CONNECTION, (socket) => {

  // move this to io.use()
  socket.on(SOCKET_EVENTS.LOGIN, async (data) => {
    const doc = await prisma.user.findFirst({
      where: {
        user: data.user,
      },
    });

    if (await argon2.verify(doc?.pass || '', data?.pass)) {
      if (doc?.socket) {
        io.to(socket.id).emit(SOCKET_EVENTS.UPDATE_SOCKET, { socket: doc.socket });
        socket.disconnect();
      } else {
        await prisma.user.updateMany({
          where: {
            user: data.user,
          },
          data: {
            socket: socket.id,
            exp: new Date().getTime() + days
          }
        });
        io.to(socket.id).emit(SOCKET_EVENTS.UPDATE_SOCKET, { socket: socket.id });
      }
    } else {
      socket.disconnect();
    }
  });

  socket.on(SOCKET_EVENTS.DISCONNECT, async () => {
    await prisma.user.updateMany({
      where: {
        socket: socket.id,
      },
      data: {
        socket: null,
        exp: new Date().getTime() + days
      }
    });
  });

  // Insecure, in person or other medium preferred, create X3 Diffie Hellman protocol
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  socket.on('key-exchange', () => {});

  socket.on(SOCKET_EVENTS.SEND_REQUEST, async (friend) => {
    const doc = await prisma.user.findFirst({
      where: {
        user: friend,
      },
    });
    if (doc !== null && doc?.socket) {
      console.log(doc);
    }
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

const startServer = async () => {
  await prisma.$connect();
  server.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
}

startServer().catch((e) => {
  console.error(e);
  throw e;
}).finally(async () => {
  await prisma.$disconnect();
});

