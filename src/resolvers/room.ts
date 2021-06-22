import { Room } from "../entities/Room";
import { Arg, Ctx, Field, FieldResolver, Int, Mutation, ObjectType, Publisher, PubSub, Query, Resolver, Root, Subscription, UseMiddleware } from "type-graphql";
import { MyContext } from "../types";
import { isAuth } from "../middleware/isAuth";
import { getConnection, LessThan } from "typeorm";
import { UserRoom } from "../entities/UserRoom";
import { User } from "../entities/User";
import { RoomSound } from "../entities/RoomSound";
import FfmpegCommand from 'fluent-ffmpeg';

@ObjectType()
class PaginatedRooms {
    @Field(() => [Room])
    rooms: Room[];
    @Field()
    hasMore: boolean;
}

@Resolver(Room)
export class RoomResolver {
    @FieldResolver(() => String)
    nameSnippet(@Root() room: Room) {
        const limit = 50;
        let newName = room.name.slice(0, limit - 3);
        if (room.name.length >= limit)
            newName + "...";
        return newName;
    }

    @FieldResolver(() => User)
    async creator(@Root() room: Room,
        @Ctx() { userLoader }: MyContext
    ) {
        return userLoader.load(room.creatorId);
    }

    @FieldResolver(() => UserRoom)
    async userRooms(@Root() room: Room,
        @Ctx() { userRoomLoader }: MyContext
    ) {
        return userRoomLoader.load(room.id);
    }


    @Mutation(() => Boolean)
    @UseMiddleware(isAuth)
    async addUser(
        @Arg('roomId', () => Int) roomId: number,
        @Arg('usernameOrEmail') usernameOrEmail: string,
        @PubSub("ROOMS") publish: Publisher<Room>
        // @Ctx() { req }: MyContext
    ) {
        const user = await User.findOne(
            usernameOrEmail.includes('@')
                ? { where: { email: usernameOrEmail } }
                : { where: { username: usernameOrEmail } });
        if (!user) {
            return {
                errors: [
                    {
                        field: "usernameOrEmail",
                        message: "Username doesn't exist",
                    },
                ],
            };
        }
        const userRoom = await UserRoom.findOne({ where: { user, roomId } })
        if (!userRoom) {
            await UserRoom.insert({
                userId: user.id,
                roomId,
            });
        } else {
            return false;
        }
        const room = await Room.findOne(roomId, { relations: ["roomSounds"] });
        if (room) {
            await publish(room);
        }
        return true;
    }



    @Query(() => PaginatedRooms)
    async rooms(
        @Arg('limit', () => Int) limit: number,
        @Arg('cursor', () => String, { nullable: true }) cursor: string | null,
    ): Promise<PaginatedRooms> {
        const realLimit = Math.min(50, limit) + 1;
        const realLimitPlusOne = realLimit + 1;

        const replacements: any[] = [realLimitPlusOne];

        if (cursor) {
            replacements.push(new Date(parseInt(cursor)));
        }

        let where = {};
        if (cursor) {
            where = { createdAt: LessThan(cursor) };
        }

        const room = await Room.find({ order: { createdAt: "DESC" }, take: realLimitPlusOne, where });


        // const qb = await getConnection()
        //     .getRepository(Room)
        //     .createQueryBuilder("r")
        //     .innerJoinAndSelect("r.creator", "u")
        //     .orderBy('r."createdAt"', "DESC")
        //     .take(realLimitPlusOne);

        // if (cursor) {
        //     qb.where('r."createdAt" < :cursor', {
        //         cursor: new Date(parseInt(cursor))
        //     });
        // }
        // const rooms2 = await qb.getMany();

        return {
            rooms: room.slice(0, realLimit),
            hasMore: room.length === realLimitPlusOne
        };
    }

    @Query(() => Room, { nullable: true })
    async room(
        @Arg('id', () => Int) id: number,
        // @Ctx() { req }: MyContext
    ): Promise<Room | undefined> {
        const repo = await getConnection().getRepository(Room);
        const room = await repo.findOne(id, { relations: ["roomSounds"] });
        return room;
    }
    @Mutation(() => Room)
    @UseMiddleware(isAuth)
    async createRoom(
        @Arg('input') input: string,
        @Ctx() { req }: MyContext
    ): Promise<Room> {
        const userId = req.session.userId;
        const room = await Room.create({
            name: input,
            creatorId: userId,
        }).save();
        const user = await User.findOne({ id: userId })
        await UserRoom.insert({
            userId: user!.id,
            roomId: room.id,
        });
        return room;
    }
    @Mutation(() => Room, { nullable: true })
    async updateRoom(
        @Arg('id') id: number,
        @Arg('name') name: string
    ): Promise<Room | null> {
        const room = await Room.findOne(id);
        if (!room) {
            return null;
        }
        if (typeof name !== 'undefined') {
            await Room.update({ id }, { name });
        }
        return room;
    }
    @Mutation(() => Boolean)
    async deleteRoom(
        @Arg('id') id: number,
    ): Promise<boolean> {
        try {
            await Room.delete(id);
        } catch {
            return false;
        }
        return true;
    }
    @Mutation(() => RoomSound)
    @UseMiddleware(isAuth)
    async updateTrack(
        @Arg('roomId', () => Int) roomId: number,
        @Arg('trackId', () => Int) trackId: number,
        @Arg('track', () => [String]) track: string[],
        @PubSub("ROOMS") publish: Publisher<Room>
    ): Promise<RoomSound | null> {
        let roomSound = await RoomSound.findOne({ where: { trackId, roomId } })
        if (!roomSound) {
            roomSound = await RoomSound.create({
                roomId,
                track,
                trackId
            })
        } else {
            roomSound.track = track;
        }
        await roomSound.save();
        const repo = await getConnection().getRepository(Room);
        const room = await repo.findOne(roomId, { relations: ["roomSounds"] });
        if (room) {
            await publish(room);
        }
        return roomSound;

    }
    @Mutation(() => Boolean)
    @UseMiddleware(isAuth)
    async concat(
        @Arg('roomId', () => Int) roomId: number,
        @PubSub("ROOMS") publish: Publisher<Room>
    ): Promise<Boolean> {          
        const roomSounds = await RoomSound.find({ roomId });
        const room = await Room.findOne(roomId, { relations: ["roomSounds"] });
        roomSounds.forEach(rs => {
            const com = FfmpegCommand();
            rs.track.forEach(t => {
                com.input(t);
                if (t.includes("piano_"))
                    com.inputOptions("-ss 00:00:0.0").inputOptions("-t 0.5");
            })
            com.on('error', function (err: any) {
                console.log('An error occurred: ' + err.message);
                return false;
            })
                .on('end', function () {
                    console.log('Finished');
                })
                .mergeToFile(`public/sounds/outputs/${roomId}.mp3`);
        })

        if (room) {
            await publish(room);
        }
        return true;
    }
    @Subscription({
        topics: "ROOMS",
    })
    roomChanges(
        @Root() roomPayload: Room,
    ): Room {
        return roomPayload;

    }
}