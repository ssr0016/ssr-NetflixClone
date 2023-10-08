import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import prisma from '@/lib/prismadb';
import { compare } from 'bcrypt'; 
// compare import from bcrypt


export default NextAuth({
    providers: [
        Credentials({
            id: 'crendetials',
            name: 'Credentials',
            credentials: {
                email: {
                    label: 'Email',
                    type:'text',
                },
                password: {
                    label: 'Password',
                    type: 'password',
                }
            },
            async authorize(credentials) {
                //if credentials is missing
                if(!credentials?.email || !credentials?.password){
                    throw new Error('Email and Password required');
                }
                
                const user = await prismadb.user.findUnique({
                    where: {
                        email: credentials.email
                    }
                });

                //check the user if actually exist
                if(!user || !user.hashedPassword){
                    throw new Error('Email does not exist');
                }

                const isCorrectPassword = await compare(
                    credentials.password,
                    user.hashedPassword
                );

                if(!isCorrectPassword){
                    throw new Error('Incorrect password');
                }

                return user;
            }
        })
    ],
    pages: {
        
    }
})