import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { scanProject } from "../src/core/scan.js";
import {
  analyzeFirebaseRules,
  analyzeSupabaseSql,
  supabasePolicyIsAuthenticationOnly,
  supabasePolicyIsUnconditional,
  supabasePolicyUsesUserMetadata,
} from "../src/detectors/baas-policy.js";

test("Supabase policy analysis respects permissive, restrictive and client-role boundaries", () => {
  const source = `
-- create policy "comment decoy" on public.documents using (true);
create table public.documents (id uuid, owner_id uuid, tenant_id uuid);
alter table public.documents enable row level security;

create policy "owner read" on public.documents
  for select to authenticated
  using ((select auth.uid()) = owner_id);

create policy "signed-in read" on public.documents
  as permissive for select to "authenticated"
  using ((select auth.uid()) is not null);

create policy "restrictive session gate" on public.documents
  as restrictive for select to authenticated
  using (auth.uid() is not null);

create policy "service maintenance" on public.documents
  for all to service_role using (true) with check (true);

create policy "unsafe tenant claim" on public.documents
  for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'tenant_id')::uuid = tenant_id);

create policy "metadata text is not a claim" on public.documents
  for select to authenticated
  using (description = 'auth.jwt() user_metadata');

create policy "row metadata is not jwt metadata" on public.documents
  for select to authenticated
  using (auth.jwt() is not null and user_metadata = expected_metadata);

create function policy_example() returns text language sql as $$
  select 'create policy "function decoy" on public.documents using (true)';
$$;
`;
  const analysis = analyzeSupabaseSql(source);
  assert.deepEqual(analysis.createdTables.map((item) => item.table), ["public.documents"]);
  assert.deepEqual(analysis.rlsTables, ["public.documents"]);
  assert.equal(analysis.policies.length, 7);
  assert.deepEqual(analysis.partialReasons, []);
  assert.equal(analysis.policies.filter(supabasePolicyIsUnconditional).length, 0);
  assert.deepEqual(analysis.policies.filter(supabasePolicyIsAuthenticationOnly).map((item) => item.table), ["public.documents"]);
  assert.deepEqual(analysis.policies.filter(supabasePolicyUsesUserMetadata).map((item) => item.table), ["public.documents"]);
});

test("Supabase unconditional analysis catches omitted predicates but not safe defaults", () => {
  const analysis = analyzeSupabaseSql(`
create policy public_read on public.posts for select to anon using (true);
create policy implicit_public on public.posts for select to authenticated;
create policy signed_in_or_owner on public.posts for select to authenticated
  using (auth.uid() is not null or auth.uid() = owner_id);
create policy safe_insert on public.posts for insert to authenticated
  with check (auth.uid() = owner_id);
create policy safe_update on public.posts for update to authenticated
  using (auth.uid() = owner_id);
`);
  assert.equal(analysis.policies.length, 5);
  assert.deepEqual(analysis.policies.map(supabasePolicyIsUnconditional), [true, true, false, false, false]);
  assert.deepEqual(analysis.policies.map(supabasePolicyIsAuthenticationOnly), [false, false, true, false, false]);
});

test("Firebase analysis expands simple auth helpers while retaining object-bound helpers", () => {
  const analysis = analyzeFirebaseRules(`
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() {
      return request.auth != null;
    }
    function owns(userId) {
      return request.auth != null && request.auth.uid == userId;
    }
    match /profiles/{userId} {
      allow read: if owns(userId);
      allow update: if signedIn();
      allow delete: if signedIn() || request.auth.uid == userId;
    }
    // allow write: if true;
    function decoy() { return "allow delete: if true;"; }
  }
}
`);
  assert.equal(analysis.service, "firestore");
  assert.equal(analysis.allows.length, 3);
  assert.equal(analysis.allows[0]?.authenticationOnly, false);
  assert.equal(analysis.allows[1]?.authenticationOnly, true);
  assert.equal(analysis.allows[2]?.authenticationOnly, true);
  assert.equal(analysis.allows.some((item) => item.unconditional), false);
  assert.deepEqual(analysis.partialReasons, []);
});

test("Firebase Storage analysis distinguishes bounded uploads from auth-only unbounded uploads", () => {
  const analysis = analyzeFirebaseRules(`
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    function validSize() {
      return request.resource.size < 5 * 1024 * 1024;
    }
    function below(size) {
      return request.resource.size < size;
    }
    match /users/{userId}/{fileName} {
      allow write: if request.auth != null
        && request.auth.uid == userId
        && validSize();
      allow create: if request.auth != null;
      allow update: if request.auth.uid == userId
        && request.resource.metadata.note == "request.resource.size < 1";
      allow update: if request.auth.uid == userId
        && below(5 * 1024 * 1024);
    }
  }
}
`);
  assert.equal(analysis.service, "storage");
  assert.equal(analysis.allows.length, 4);
  assert.equal(analysis.allows[0]?.storageUploadWithoutSizeLimit, false);
  assert.equal(analysis.allows[1]?.storageUploadWithoutSizeLimit, true);
  assert.equal(analysis.allows[1]?.authenticationOnly, true);
  assert.equal(analysis.allows[2]?.storageUploadWithoutSizeLimit, true);
  assert.equal(analysis.allows[3]?.storageUploadWithoutSizeLimit, false);
  assert.deepEqual(analysis.partialReasons, []);
});

test("unsupported Firebase Storage helper semantics make coverage partial instead of clean", () => {
  const analysis = analyzeFirebaseRules(`
service firebase.storage {
  match /b/{bucket}/o {
    function validUpload(file) {
      let maximum = 1024;
      return file.size < maximum;
    }
    match /uploads/{fileName} {
      allow create: if request.auth != null && validUpload(request.resource);
    }
  }
}
`);
  assert.equal(analysis.allows[0]?.unresolvedLocalHelper, true);
  assert.equal(analysis.allows[0]?.storageUploadWithoutSizeLimit, false);
  assert.match(analysis.partialReasons.join("; "), /outside the bounded single-return model/);
});

test("malformed bounded policy input produces partial analysis", () => {
  const sql = analyzeSupabaseSql("create policy broken on public.posts using (auth.uid() = owner_id;");
  assert.match(sql.partialReasons.join("; "), /unbalanced expression/);

  const firebase = analyzeFirebaseRules("service cloud.firestore { match /x/{id} { allow read: if request.auth != null");
  assert.match(firebase.partialReasons.join("; "), /not terminated/);

  const quoted = analyzeSupabaseSql("create policy broken on public.posts using ('unterminated");
  assert.match(quoted.partialReasons.join("; "), /quoted value is not terminated/);
});

test("deeply nested and duplicate-helper input fails closed", () => {
  const nested = `${"(".repeat(65)}request.auth != null${")".repeat(65)}`;
  const firebase = analyzeFirebaseRules(`
service cloud.firestore {
  function signedIn() { return request.auth != null; }
  function signedIn() { return true; }
  match /x/{id} { allow read: if signedIn(); }
  match /y/{id} { allow read: if ${nested}; }
}
`);
  assert.equal(firebase.allows[0]?.unresolvedLocalHelper, true);
  assert.equal(firebase.allows[0]?.authenticationOnly, false);
  assert.match(firebase.partialReasons.join("; "), /declared more than once/);
  assert.match(firebase.partialReasons.join("; "), /nesting levels/);

  const sql = analyzeSupabaseSql(`create policy nested on public.posts using (${"(".repeat(65)}auth.uid() is not null${")".repeat(65)});`);
  assert.equal(sql.policies.length, 0);
  assert.match(sql.partialReasons.join("; "), /nesting levels/);
});

test("policy and statement counts are bounded", () => {
  const firebase = analyzeFirebaseRules(`service cloud.firestore { match /x/{id} { ${Array.from({ length: 2_001 }, () => "allow read: if false;").join("\n")} } }`);
  assert.equal(firebase.allows.length, 2_000);
  assert.match(firebase.partialReasons.join("; "), /allow count exceeded 2000/);

  const sql = analyzeSupabaseSql(Array.from({ length: 10_001 }, () => "select 1;").join("\n"));
  assert.match(sql.partialReasons.join("; "), /statement count exceeded 10000/);
});

test("Firebase allows may terminate at their containing block", () => {
  const analysis = analyzeFirebaseRules(`
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if true
    }
  }
}
`);
  assert.equal(analysis.allows.length, 1);
  assert.equal(analysis.allows[0]?.unconditional, true);
  assert.equal(analysis.allows[0]?.authenticationOnly, false);
  assert.equal(analysis.allows[0]?.storageUploadWithoutSizeLimit, true);
  assert.deepEqual(analysis.partialReasons, []);
});

test("a standalone Storage rules file activates Firebase BaaS scanning", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-storage-rules-"));
  try {
    await writeFile(join(temporary, "storage.rules"), `
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /uploads/{fileName} {
      allow create: if request.auth != null;
    }
  }
}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.baas.includes("Firebase"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "firebase.authenticated-access-without-resource-check"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "firebase.storage-upload-without-size-limit"));
    assert.equal(report.coverage.find((item) => item.domain === "baas-authorization")?.status, "complete");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
