INSERT INTO public.roles (role_name)
VALUES ('user')
ON CONFLICT (role_name) DO NOTHING;