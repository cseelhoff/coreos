DATABASES = {
    'default': {
        'ATOMIC_REQUESTS': True,
        'ENGINE': 'awx.main.db.profiled_pg',
        'NAME': "awx",
        'USER': "awx",
        'PASSWORD': "rzabMdUaDNuyQGmnYUQN",
        'HOST': "postgres",
        'PORT': "5432",
    }
}