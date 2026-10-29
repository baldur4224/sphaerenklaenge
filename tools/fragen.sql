-- SphärenKlänge: Fragen & Empfindungen
-- Speicher in Supabase. Einmal im SQL-Editor des Supabase-Projekts ausführen.
--
-- Besucher dürfen nur neue Beiträge schreiben (ohne Antwort, unsichtbar) und nur
-- beantwortete, freigegebene Beiträge lesen. Alles andere (Liste aller Beiträge,
-- antworten, verbergen, löschen) geht nur über die bs_*-Funktionen mit dem
-- Backstage-Zugang. Der Zugang ist ein Prüfwert, den die Seite beim Backstage-Login
-- aus dem Passwort berechnet; hier liegt davon nur ein bcrypt-Hash.
-- Die erste erfolgreiche Backstage-Anmeldung nach dem Einrichten legt ihn fest.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.beitraege (
  id uuid primary key default gen_random_uuid(),
  erstellt timestamptz not null default now(),
  name text check (name is null or char_length(name) <= 60),
  lied text check (lied is null or char_length(lied) <= 150),
  text text not null check (char_length(text) between 2 and 2000),
  antwort text check (antwort is null or char_length(antwort) <= 4000),
  beantwortet timestamptz,
  sichtbar boolean not null default false
);

alter table public.beitraege enable row level security;
revoke all on public.beitraege from anon, authenticated;
grant insert (name, lied, text) on public.beitraege to anon, authenticated;
grant select (id, erstellt, name, lied, text, antwort, beantwortet) on public.beitraege to anon, authenticated;

drop policy if exists "neu schreiben" on public.beitraege;
create policy "neu schreiben" on public.beitraege for insert to anon, authenticated
  with check (antwort is null and beantwortet is null and sichtbar = false);
drop policy if exists "beantwortete lesen" on public.beitraege;
create policy "beantwortete lesen" on public.beitraege for select to anon, authenticated
  using (sichtbar);

-- Schutz vor Überflutung: höchstens 40 neue, unbeantwortete Beiträge pro Stunde.
create or replace function public.beitraege_bremse() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if (select count(*) from public.beitraege
      where not sichtbar and erstellt > now() - interval '1 hour') >= 40 then
    raise exception 'Gerade kommen zu viele Nachrichten an. Bitte später noch einmal versuchen.';
  end if;
  return new;
end $$;
drop trigger if exists bremse on public.beitraege;
create trigger bremse before insert on public.beitraege
  for each row execute function public.beitraege_bremse();

-- Zugang (nicht über die API erreichbar)
create schema if not exists intern;
revoke all on schema intern from public, anon, authenticated;
create table if not exists intern.zugang (
  id int primary key default 1 check (id = 1),
  hash text not null
);
create table if not exists intern.fehlversuche (zeit timestamptz not null default now());

create or replace function intern.pruefen(p_token text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare h text;
begin
  delete from intern.fehlversuche where zeit < now() - interval '1 day';
  if (select count(*) from intern.fehlversuche where zeit > now() - interval '1 hour') >= 30 then
    return false;
  end if;
  select hash into h from intern.zugang where id = 1;
  if h is null or p_token is null or char_length(p_token) <> 64 then
    insert into intern.fehlversuche default values;
    return false;
  end if;
  if extensions.crypt(p_token, h) = h then return true; end if;
  insert into intern.fehlversuche default values;
  return false;
end $$;

create or replace function public.bs_einrichten(p_token text) returns text
language plpgsql security definer set search_path = '' as $$
begin
  if exists (select 1 from intern.zugang) then
    return case when intern.pruefen(p_token) then 'ok' else 'nein' end;
  end if;
  if p_token is null or char_length(p_token) <> 64 then return 'nein'; end if;
  insert into intern.zugang (id, hash) values (1, extensions.crypt(p_token, extensions.gen_salt('bf', 10)));
  return 'neu';
end $$;

create or replace function public.bs_liste(p_token text) returns json
language plpgsql security definer set search_path = '' as $$
begin
  if not intern.pruefen(p_token) then return null; end if;
  return coalesce((select json_agg(b order by b.erstellt desc) from public.beitraege b), '[]'::json);
end $$;

create or replace function public.bs_antworten(p_token text, p_id uuid, p_antwort text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare a text := nullif(btrim(coalesce(p_antwort, '')), '');
begin
  if not intern.pruefen(p_token) then return false; end if;
  update public.beitraege
     set antwort = a,
         beantwortet = case when a is null then null else now() end,
         sichtbar = a is not null
   where id = p_id;
  return found;
end $$;

create or replace function public.bs_sichtbar(p_token text, p_id uuid, p_sichtbar boolean) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  if not intern.pruefen(p_token) then return false; end if;
  update public.beitraege set sichtbar = p_sichtbar and antwort is not null where id = p_id;
  return found;
end $$;

create or replace function public.bs_loeschen(p_token text, p_id uuid) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  if not intern.pruefen(p_token) then return false; end if;
  delete from public.beitraege where id = p_id;
  return found;
end $$;

revoke all on function intern.pruefen(text) from public, anon, authenticated;
revoke all on function public.beitraege_bremse() from public, anon, authenticated;
revoke all on function public.bs_einrichten(text), public.bs_liste(text),
  public.bs_antworten(text, uuid, text), public.bs_sichtbar(text, uuid, boolean),
  public.bs_loeschen(text, uuid) from public;
grant execute on function public.bs_einrichten(text), public.bs_liste(text),
  public.bs_antworten(text, uuid, text), public.bs_sichtbar(text, uuid, boolean),
  public.bs_loeschen(text, uuid) to anon, authenticated;

-- Ergänzung: wer antwortet (Baldur oder Caro-Dame)
alter table public.beitraege add column if not exists antwort_von text
  check (antwort_von is null or antwort_von in ('Baldur', 'Caro-Dame'));
grant select (antwort_von) on public.beitraege to anon, authenticated;

create or replace function public.bs_antworten(p_token text, p_id uuid, p_antwort text, p_von text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
  a text := nullif(btrim(coalesce(p_antwort, '')), '');
  v text := case when p_von in ('Baldur', 'Caro-Dame') then p_von else 'Baldur' end;
begin
  if not intern.pruefen(p_token) then return false; end if;
  update public.beitraege
     set antwort = a,
         antwort_von = case when a is null then null else v end,
         beantwortet = case when a is null then null else now() end,
         sichtbar = a is not null
   where id = p_id;
  return found;
end $$;
revoke all on function public.bs_antworten(text, uuid, text, text) from public;
grant execute on function public.bs_antworten(text, uuid, text, text) to anon, authenticated;

-- Ergänzung: private Fragen. Die Seite erzeugt pro Frage einen geheimen Code und behält ihn im Browser;
-- gespeichert wird nur dessen SHA-256. Nur wer den Code zeigt, bekommt Frage und Antwort zurück.
alter table public.beitraege add column if not exists privat boolean not null default false;
alter table public.beitraege add column if not exists schluessel text check (schluessel is null or schluessel ~ '^[0-9a-f]{64}$');
alter table public.beitraege add constraint privat_braucht_schluessel check (not privat or schluessel is not null);
grant insert (privat, schluessel) on public.beitraege to anon, authenticated;
alter policy "beantwortete lesen" on public.beitraege using (sichtbar and not privat);

create or replace function public.meine_fragen(p_codes text[]) returns json
language plpgsql security definer set search_path = '' as $$
begin
  if p_codes is null or cardinality(p_codes) = 0 or cardinality(p_codes) > 50 then return '[]'::json; end if;
  return coalesce((
    select json_agg(json_build_object('id', b.id, 'erstellt', b.erstellt, 'name', b.name, 'lied', b.lied, 'text', b.text,
                                      'antwort', b.antwort, 'antwort_von', b.antwort_von, 'beantwortet', b.beantwortet)
                    order by b.erstellt desc)
      from public.beitraege b
     where b.privat
       and b.schluessel in (select encode(extensions.digest(c, 'sha256'), 'hex') from unnest(p_codes) c where char_length(c) = 64)
  ), '[]'::json);
end $$;
grant execute on function public.meine_fragen(text[]) to anon, authenticated;

-- Ergänzung: Löschen im Backstage. Supabase lässt hier keine DELETE-Befehle ohne Rückfrage zu,
-- darum leert bs_entfernen den Beitrag (Text, Name, Antwort, Schlüssel) und blendet ihn überall aus.
alter table public.beitraege add column if not exists geloescht boolean not null default false;
alter policy "beantwortete lesen" on public.beitraege using (sichtbar and not privat and not geloescht);

create or replace function public.bs_liste(p_token text) returns json
language plpgsql security definer set search_path = '' as $$
begin
  if not intern.pruefen(p_token) then return null; end if;
  return coalesce((select json_agg(b order by b.erstellt desc) from public.beitraege b where not b.geloescht), '[]'::json);
end $$;

create or replace function public.bs_entfernen(p_token text, p_id uuid) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  if not intern.pruefen(p_token) then return false; end if;
  update public.beitraege
     set geloescht = true, sichtbar = false, text = '(gelöscht)', name = null, antwort = null, schluessel = null, privat = false
   where id = p_id;
  return found;
end $$;
grant execute on function public.bs_entfernen(text, uuid) to anon, authenticated;

create or replace function public.meine_fragen(p_codes text[]) returns json
language plpgsql security definer set search_path = '' as $$
begin
  if p_codes is null or cardinality(p_codes) = 0 or cardinality(p_codes) > 50 then return '[]'::json; end if;
  return coalesce((
    select json_agg(json_build_object('id', b.id, 'erstellt', b.erstellt, 'name', b.name, 'lied', b.lied, 'text', b.text,
                                      'antwort', b.antwort, 'antwort_von', b.antwort_von, 'beantwortet', b.beantwortet)
                    order by b.erstellt desc)
      from public.beitraege b
     where b.privat and not b.geloescht
       and b.schluessel in (select encode(extensions.digest(c, 'sha256'), 'hex') from unnest(p_codes) c where char_length(c) = 64)
  ), '[]'::json);
end $$;
