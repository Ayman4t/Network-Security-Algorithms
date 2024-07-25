using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
       public string Encrypt(string plainText, string key)
        {
            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };


            int temp = 0;
            plainText = plainText.ToLower();
            key = key.ToLower();
            string encreptedText = "";

            while (key.Length != plainText.Length)
            {
                key = key + key[temp];
                temp++;
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                char letter = plainText[i];
                char letterofkey = key[i];
                int index1 = Array.IndexOf(alphabet, letter);
                int index2 = Array.IndexOf(alphabet, letterofkey);
                int indexOfCipher = (index2 + index1) % 26;

                encreptedText += alphabet[indexOfCipher];
            }

            return encreptedText;
        }
        public string Decrypt(string cipherText, string key)
        {
            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

            int temp = 0;
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string plainText = "";

            while (key.Length != cipherText.Length)
            {
                key = key + key[temp];
                temp++;
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                char letter = cipherText[i];
                char letterofkey = key[i];
                int index1 = Array.IndexOf(alphabet, letter);
                int index2 = Array.IndexOf(alphabet, letterofkey);
                int indexOfPlain = (index1 - index2 + 26) % 26;

                plainText += alphabet[indexOfPlain];
            }

            return plainText;

        }

        
        public string Analyse(string plainText, string cipherText)
        {
            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

            cipherText = cipherText.ToLower();
            string key = "";
            string key_stream = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                char letter = cipherText[i];
                char letterofkey = plainText[i];
                int index1 = Array.IndexOf(alphabet, letter);
                int index2 = Array.IndexOf(alphabet, letterofkey);
                int indexOfkey_stream = (index1 - index2 + 26) % 26;

                key_stream += alphabet[indexOfkey_stream];
            }
            key = key + key_stream[0];

            for (int i = 1; i < key_stream.Length; i++)
            {
                string en = Encrypt(plainText, key);
                if (cipherText.Equals(en))
                {
                    return key;
                }
                key = key + key_stream[i];
            }
            return key_stream;

        }

    }
}
