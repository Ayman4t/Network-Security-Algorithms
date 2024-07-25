using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            char[] result = new char[plainText.Length];
            string ct = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char character = plainText[i];

                // Check if the character is a letter
                if (char.IsLetter(character))
                {
                    // Determine whether the character is uppercase or lowercase
                    char offset = char.IsUpper(character) ? 'A' : 'a';
                    // Apply the Caesar Cipher shift
                    result[i] = (char)((character + key - offset) % 26 + offset);
                }
                else
                {
                    // Non-alphabetic characters remain unchanged
                    result[i] = character;
                }
                ct += result[i];
            }

            return ct;
        }

        public string Decrypt(string cipherText, int key)
        {
            key = (key % 26 + 26) % 26;

            char[] result = new char[cipherText.Length];
            string pt = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                char character = cipherText[i];

                if (char.IsLetter(character))
                {
                    char offset = char.IsUpper(character) ? 'A' : 'a';
                    result[i] = (char)(((character - offset - key + 26) % 26) + offset);
                    pt += result[i];
                }
                else
                {
                    result[i] = character;
                    pt += result[i];
                }
            }

            return pt;
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            int num = cipherText[0] - plainText[0];
            if (num >= 0)
            {
                return num;
            }
            else
            {
                while (true)
                {
                    num = num + 26;
                    if (num >= 0)
                    {
                        break;
                    }
                }
                return num;
            }
        }
    }
}
