import { User } from "../entities/User";
import { MyContext } from "../types";
import { Arg, Ctx, Field, FieldResolver, Int, Mutation, ObjectType, Publisher, PubSub, Query, Resolver, Root, Subscription } from "type-graphql";
import argon2 from 'argon2'
import { FORGET_PASSWORD_PREFIX } from "../constants";
import { UsernamePasswordInput } from "../utils/UsernamePasswordInput";
import { validateRegister } from "../utils/validateRegister";
import { sendEmail } from "../utils/sendEmail";
import { v4 } from "uuid";
import { getConnection } from "typeorm";
import { hash, compare } from "bcryptjs";
import { createAccessToken } from "../utils/auth";
// import { sendRefreshToken } from "../utils/sendRefreshToken";
import { verify } from "jsonwebtoken";


@ObjectType()
class FieldError {
    @Field()
    field: string;
    @Field()
    message: string;
}

@ObjectType()
class UserResponse {
    @Field(() => [FieldError], { nullable: true })
    errors?: FieldError[];
    @Field(() => User, { nullable: true })
    user?: User;
}
@ObjectType()
class LoginResponse {
    @Field(() => [FieldError], { nullable: true })
    errors?: FieldError[];
    @Field(() => String, { nullable: true })
    accessToken?: string;
    @Field(() => User, { nullable: true })
    user?: User;
}

@Resolver(User)
export class UserResolver {
    @FieldResolver(() => String)
    email(@Root() user: User,
        @Ctx() { payload }: MyContext
    ) {
        if (payload?.userId === user.id) {
            return user.email;
        }
        return "";
    }

    @Mutation(() => UserResponse)
    async changePassword(
        @Arg('token') token: string,
        @Arg('newPassword') newPassword: string,
        @Ctx() { req, redis }: MyContext
    ): Promise<UserResponse> {
        if (newPassword.length <= 3) {
            return {
                errors: [
                    {
                        field: "newPassword",
                        message: "Length must be greater than 3",
                    },
                ]
            };
        }
        const key = FORGET_PASSWORD_PREFIX + token;
        const userId = await redis.get(key);
        if (!userId) {
            return {
                errors: [
                    {
                        field: "token",
                        message: "Token expired",
                    },
                ],
            };
        }
        const userIdNum = parseInt(userId);
        const user = await User.findOne(userIdNum);
        if (!user) {
            return {
                errors: [
                    {
                        field: "token",
                        message: "User no longer exists",
                    },
                ],
            };
        }

        await User.update(
            { id: userIdNum },
            {
                password: await argon2.hash(newPassword),
            }
        );

        await redis.del(key);

        req.session.userId = user.id;
        return { user };

    }


    @Mutation(() => Boolean)
    async forgotPassword(
        @Arg('email') email: string,
        @Ctx() { redis }: MyContext
    ) {
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return true;
        }
        const token = v4();

        await redis.set(FORGET_PASSWORD_PREFIX + token,
            user.id,
            'ex',
            1000 * 60 * 60 * 24 * 3
        ); //3 days

        sendEmail(
            email,
            `<a href="${process.env.CORS_ORIGIN}/change-password/${token}">reset password</a>`
        );
        return true;
    }

    @Query(() => User, { nullable: true })
    me(@Ctx() {req}: MyContext) {
        const authorization = req.headers["authorization"];

        if (!authorization) {
            return null;
        }

        try {
            const token = authorization.split(" ")[1];
            const payload: any = verify(token, process.env.ACCESS_TOKEN_SECRET!);
            return User.findOne(payload.userId);
        } catch (err) {
            console.log(err);
            return null;
        }
    }


    @Mutation(() => LoginResponse)
    async register(
        @Arg('options') options: UsernamePasswordInput,
        @Ctx() {  }: MyContext
    ): Promise<LoginResponse> {
        const errors = validateRegister(options);
        if (errors) {
            return { errors };
        }

        const hashedPassword = await hash(options.password, 12);
        let user;
        try {
            //User.create({}).save()
            const result = await getConnection().createQueryBuilder().insert().into(User).values(
                {
                    username: options.username,
                    email: options.email,
                    password: hashedPassword,
                    location: null
                }
            )
                .returning('*')
                .execute();
            user = result.raw[0];
        } catch (err) {
            if (err.code === '23505') {
                return {
                    errors: [
                        {
                            field: "username",
                            message: "Username already taken",
                        },
                    ],
                };
            }

        }
        // sendRefreshToken(res, createRefreshToken(user));

        return {
            accessToken: createAccessToken(user),
            user
        };

    }
    @Mutation(() => LoginResponse)
    async login(
        @Arg('usernameOrEmail') usernameOrEmail: string,
        @Arg('password') password: string,
        @Ctx() {  }: MyContext
    ): Promise<LoginResponse> {
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

        const valid = await compare(password, user.password);
        if (!valid) {
            return {
                errors: [
                    {
                        field: "password",
                        message: "Incorrect password",
                    },
                ],
            };
        }
        // sendRefreshToken(res, createRefreshToken(user));

        return {
            accessToken: createAccessToken(user),
            user,
        };
    }

    @Mutation(() => Boolean)
    async logout(@Ctx() {  }: MyContext) {
        // sendRefreshToken(res, "");

        return true;
    }

    @Mutation(() => Boolean)
    async revokeRefreshTokensForUser(@Arg("userId", () => Int) userId: number) {
        await getConnection()
            .getRepository(User)
            .increment({ id: userId }, "tokenVersion", 1);

        return true;
    }
    @Mutation(() => Boolean)
    async setLocation(
        @Arg('location') location: string,
        @PubSub("USERS") publish: Publisher<User>,
        @Ctx() { req }: MyContext
    ) {
        const authorization = req.headers["authorization"];

        if (!authorization) {
            return null;
        }

        try {
            const token = authorization.split(" ")[1];
            const payload: any = verify(token, process.env.ACCESS_TOKEN_SECRET!);
            const user = await User.findOne(payload.userId);
            if (user) {
                user.location = location;
                await user.save();
                await publish(user);
            }
            return true;
        } catch (err) {
            console.log(err);
            return null;
        }

    }
    @Subscription({
        topics: "USERS",
    })
    userChanges(
        @Root() userPayload: User,
    ): User {
        return userPayload;

    }
}