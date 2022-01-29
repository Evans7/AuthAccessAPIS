import unittest

from app import app

class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        self.client = app.test_client()
        self.user_to_make_admin=17
        user_token= "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiJiNzFlNzdkZi04ZDFmLTRlNjktOTRkNC05OWIyMjNhZmYwNjAiLCJleHAiOjE2NDM0NDk4MTMsInJvbGVzIjpbInVzZXIiXX0.RpJ9u-pncUs6JiBFzrnZWPp8NyXvZB1htBibCHx7Gew"
        admin_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiI0NGQ3MDk4Zi0xYmFlLTQ0MmQtODdhOS1iZDI2ZWVjOGUzY2YiLCJleHAiOjE2NDM0NDk3ODAsInJvbGVzIjpbImFkbWluIl19.3bil6sYZjANBS9fy0siOE41MJUCUSFTtBsQ_4wAOMTE"
        self.headers_admin = {'Content-Type': 'application/json', 'x-access-token': admin_token}
        self.headers_user= {'Content-Type': 'application/json', 'x-access-token': user_token}
    def tearDown(self):
        self.ctx.pop()
    
    def test_user(self):
        rv = self.client.get('/admin/users', headers=self.headers_admin)
        self.assertEqual(rv.status_code, 200)

    def test_user_not_authorized(self):
        rv = self.client.get('/admin/users' , headers=self.headers_user)
        self.assertEqual(rv.status_code, 401)

    def test_role_add_missing(self):
        rv= self.client.post('/admin/user/role/add',headers=self.headers_admin)
        self.assertEqual(rv.status_code, 400)
    
    def test_role_add_unauthorized(self):
        rv= self.client.post('/admin/user/role/add',headers=self.headers_user)
        self.assertEqual(rv.status_code, 401)
    
    def test_role_add_existing(self):
        rv= self.client.post('/admin/user/role/add',headers=self.headers_admin,content_type='multipart/form-data',data={'user_id':'5','role_name':'admin'})
        self.assertEqual(rv.status_code, 202)

    def test_specific_user_missing(self):
        rv= self.client.get('/user/')
        self.assertEqual(rv.status_code,401)

    def test_specific_user_normal(self):
        rv= self.client.get('/user/',headers=self.headers_user)
        self.assertEqual(rv.status_code, 200)

    def test_specific_user_admin_same(self):
        rv=self.client.get('/user/',headers=self.headers_admin)
        self.assertEqual(rv.status_code,200)
    
    def test_specific_user_admin(self):
        rv=self.client.get('/user/2',headers=self.headers_admin)
        self.assertEqual(rv.status_code,200)

    def test_specific_admin_user(self):
        rv=self.client.get('/user/2',headers=self.headers_user)
        self.assertEqual(rv.status_code,401)

    def test_role_add(self):
        rv= self.client.post('/admin/user/role/add',headers=self.headers_admin,content_type='multipart/form-data',data={'user_id':self.user_to_make_admin,'role_name':'admin'})
        self.assertEqual(rv.status_code, 201)
    

