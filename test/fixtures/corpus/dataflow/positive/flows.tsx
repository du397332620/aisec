declare const req: any;
declare const database: any;
declare const exec: (command: string) => void;
declare const fetch: (url: string) => Promise<unknown>;
declare const client: any;
declare const element: HTMLElement;

const sql = req.body.sql;
database.query(`select * from users where id = ${sql}`);

const command = req.body.command;
exec(command);

const url = req.query.url;
fetch(url);

const completion = await client.chat.completions.create({ messages: [] });
const generated = completion.choices[0].message.content;
eval(generated);

const html = req.body.html;
element.innerHTML = html;

const markup = req.body.markup;
export const UnsafeView = () => <div dangerouslySetInnerHTML={{ __html: markup }} />;
