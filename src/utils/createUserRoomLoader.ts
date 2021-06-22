import DataLoader from "dataloader";
import { In } from "typeorm";
import { UserRoom } from "../entities/UserRoom";

export const createUserRoomLoader = () =>
    new DataLoader<number, [UserRoom]>(
        async (roomIds) => {
        const userRoom = await UserRoom.find({relations: ["user"], where: {roomId: In(roomIds as number[])}});
        const userRoomIdsToUser: Record<number, [UserRoom]> = {};
        userRoom.forEach(uR => {
            (userRoomIdsToUser[uR.roomId] = userRoomIdsToUser[uR.roomId] || []).push(uR);                   
        });
        return roomIds.map((roomId) => userRoomIdsToUser[roomId]);
    });