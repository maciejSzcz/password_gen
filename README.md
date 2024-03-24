# Password Generator service

This is a simple password generator, which is build for Algorithm Arena weekly challenge. It is exposed publicly on fly.io [here](https://password-gen-algo-arena.fly.dev/password-gen)

The api provides one route `/password-gen`, which takes optional query parameters in the following format. Apart from more obvious parameters, it allows the user to generate a password which looks like a plausible password choice created by user. It uses markov chains to generate a password based on a file with human generated texts (in this case a leaked password file, so it's probably a bad idea to use this password, it's just a proof of concept). To enable this functionality, use `userReadable` set to true in params

## Request

| parameter       | type    | default |
| --------------- | ------- | ------- |
| minLength       | number  | 15      |
| maxLength       | number  | 0       |
| minDigits       | number  | 0       |
| minSpecialChars | number  | 0       |
| minLetters      | number  | 0       |
| userReadable    | boolean | false   |
| allUpperCase    | boolean | false   |
| allLowerCase    | boolean | false   |

Example Request

`/password-gen?minLength=10&maxLength=20&minDigits=3&minSpecialChars=2&minLetters=5&userReadable=true&allUpperCase=true`

## Response

The api responds with a json with a format of `{ error: String, password: String }`.
There are two possible status codes, 200 and 400
