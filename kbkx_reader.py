import pykeepass
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
import getpass
import json
import os
import datetime

class cryptota:
    def __init__(self, root:str):
        self.date_now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        pw = getpass.getpass()
        self.root = root
        self.log_1_path = f"{self.root}\\logs\\{self.date_now}_db_1.log"
        self.log_2_path = f"{self.root}\\logs\\{self.date_now}_db_2.log"
        self.privatekey = f"{self.root}\\keys\\my_private_rsa_key.bin"
        self.publickey = f"{self.root}\\keys\\my_rsa_public.pem"
        self.test_data = f"{self.root}\\keys\\test.bin"
        if not os.path.exists(f"{self.root}\\logs"):
            os.makedirs(f"{self.root}\\logs")
        if not os.path.exists(f"{self.root}\\keys"):
            os.makedirs(f"{self.root}\\keys")
        self.secret = pw


    def read_kbkx(self, db_1_path:str, db_2_path:str):
        kp_db_1 = pykeepass.PyKeePass(db_1_path, password=self.use_password())
        kp_db_2 = pykeepass.PyKeePass(db_2_path, password=self.use_password())
        self.db_1_name = os.path.basename(db_1_path)
        self.db_2_name = os.path.basename(db_2_path)
        self.log_db_1 = {'db_name' : self.db_1_name, 'db_path': db_1_path, 'db_logs': []}
        self.log_db_2 = {'db_name' : self.db_2_name, 'db_path': db_2_path, 'db_logs': []}

        changes_db_1 = False
        changes_db_2 = False
        for db_1_gr in kp_db_1.groups:
            finded = False
            for db_2_gr in kp_db_2.groups:
                if db_1_gr.name == db_2_gr.name:
                    finded = True
                    break
            
            if finded:
                res = self.entries_comp(db_1_gr, db_2_gr, kp_db_1, kp_db_2)
                if res['changes_db_1']:
                    changes_db_1 = str(res['changes_db_1'])
                if res['changes_db_2']:
                    changes_db_2 = str(res['changes_db_2'])
            else:
                print(f"not found in android: {db_1_gr.name}")
        
        if changes_db_1:
            kp_db_1.save()
            print('DB_1: changes_saved')
            with open(self.log_1_path, 'w', encoding='utf-8') as fi:
                fi.write(json.dumps(self.log_db_1, sort_keys=True, indent=4, ensure_ascii=False))
        if changes_db_2:
            kp_db_2.save()
            print('DB_2: changes_saved')
            with open(self.log_2_path, 'w', encoding='utf-8') as fi:
                fi.write(json.dumps(self.log_db_2, sort_keys=True, indent=4, ensure_ascii=False))


    def entries_comp(self, db_1_gr, db_2_gr, kp_db_1, kp_db_2):
        changes_db_1 = False
        changes_db_2 = False

        ## INTO DB 2
        for db_1_ent in db_1_gr.entries:
            finded = False
            for db_2_ent in db_2_gr.entries:
                if db_1_ent.title == db_2_ent.title:
                    finded = True
            
            if finded:
                pass
            else:
                print(f"not found in android: {db_1_ent.title}")
                self.create_ent(kp_db_2, db_2_gr, db_1_ent.title, db_1_ent.username, db_1_ent.password, db_1_ent.url, db_1_ent.notes)
                self.log_db_2['db_logs'].append(f"CREATED IN GROUP: {db_2_gr.name}; ENTRY: {db_1_ent.title}")
                changes_db_1 = True
        
        ## INTO DB 1
        
        for db_2_ent in db_2_gr.entries:
            finded = False
            for db_1_ent in db_1_gr.entries:
                if db_2_ent.title == db_1_ent.title:
                    finded = True
                    break
            
            if finded:
                pass
            else:
                print(f"not found in pc: {db_2_ent.title}")
                self.create_ent(kp_db_1, db_1_gr, db_2_ent.title, db_2_ent.username, db_2_ent.password, db_2_ent.url, db_2_ent.notes)
                self.log_db_1['db_logs'].append(f"CREATED IN GROUP: {db_1_gr.name}; ENTRY: {db_2_ent.title}")
                changes_db_2 = True
        return {'changes_db_1' : changes_db_1, 'changes_db_2' : changes_db_2}
    

    def create_ent(self, kp, kp_group, gr_title, ent_name, ent_pass, ent_url, ent_notes):
        kp.add_entry(kp_group, gr_title, ent_name, ent_pass, ent_url, ent_notes)


    def use_password(self):
        return self.__decode_file()

    def create_keys(self):
        key = RSA.generate(2048)
        
        encrypted_key = key.exportKey(
            passphrase=self.secret, 
            pkcs=8, 
            protection="scryptAndAES128-CBC"
        )
        
        with open(self.privatekey, 'wb') as f:
            f.write(encrypted_key)
        
        with open(self.publickey, 'wb') as f:
            f.write(key.publickey().exportKey())
    

    def encode_file(self, passwd:str):      
        with open(self.test_data, 'wb') as out_file:
            recipient_key = RSA.import_key(
                open(self.publickey).read()
            )
            
            session_key = get_random_bytes(16)
            
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            out_file.write(cipher_rsa.encrypt(session_key))
            
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            data = passwd.encode()
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)
            
            out_file.write(cipher_aes.nonce)
            out_file.write(tag)
            out_file.write(ciphertext)


    def __decode_file(self):
        with open(self.test_data, 'rb') as fobj:
            private_key = RSA.import_key(
                open(self.privatekey).read(),
                passphrase=self.secret
            )
            
            enc_session_key, nonce, tag, ciphertext = [
                fobj.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
            ]
            
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode()


if __name__ == '__main__':
    cr = cryptota(os.path.abspath(os.path.curdir)) # Инициализация с секректным паролем
    #cr.create_keys() # Создание крипто ключей в папку keys
    #cr.encode_file('password') # Создание скректно файла для хранения пароля
    #cr.read_kbkx('db_1_path','db_2_path') # Синхронизация новых записей в .kbkx файлах(позже добавлю полную синхронизацию с решением конфликтов)