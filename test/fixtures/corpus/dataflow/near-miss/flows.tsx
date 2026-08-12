declare const req: any;
declare const database: any;
declare const execFile: (command: string, args: string[]) => void;
declare const fetch: (url: string) => Promise<unknown>;
declare const client: any;
declare const element: HTMLElement;

database.query("select * from users where id = $1", [req.body.id]);
execFile("/usr/bin/printf", ["%s", req.body.message]);
fetch("https://api.example.test/status");

const completion = await client.chat.completions.create({ messages: [] });
element.textContent = completion.choices[0].message.content;
element.textContent = req.body.html;

export const SafeView = () => <div>{req.body.markup}</div>;
