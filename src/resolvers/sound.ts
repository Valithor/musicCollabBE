import { Arg, Ctx, Field, Mutation, ObjectType, Query, Resolver } from "type-graphql";
import { MyContext } from "../types";
// import { isAuth } from "../middleware/isAuth";
import { Sound } from "../entities/Sound";

@ObjectType()
class soundsLength {
    @Field(() => [Sound])
    sounds: Sound[];
    @Field()
    length: number
}

@Resolver(Sound)
export class SoundResolver {
    @Query(() => soundsLength)
    async sounds(
    ): Promise<soundsLength>{
        const sounds = await Sound.find({});
        return {
            sounds,
            length: sounds.length
        };
    }

    @Mutation(() => Sound)
    // @UseMiddleware(isAuth)
    async createSound(
        @Arg('input') input: string,
        @Ctx() { req }: MyContext
    ): Promise<Sound> {
        const userId = req.session.userId? req.session.userId:1;
        return await Sound.create({
            path: input,
            creatorId: userId,
        }).save();
    }
    @Mutation(() => Boolean)
    async deleteSound(
        @Arg('id') id: number,
    ): Promise<boolean> {
        try {
            await Sound.delete(id);
        } catch {
            return false;
        }
        return true;
    }
}