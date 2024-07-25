using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        byte[,] SBOXX = new byte[16, 16] {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

        byte[,] inverse_SBOXX = new byte[16, 16]{
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

        byte[,] R_con = new byte[10, 4] {
            {0x01, 0x00, 0x00, 0x00},
            {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00},
            {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00},
            {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00},
            {0x80, 0x00, 0x00, 0x00},
            {0x1b, 0x00, 0x00, 0x00},
            {0x36, 0x00, 0x00, 0x00} };

        byte[,] Key;

        public override string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            Key_Schedule(key);
            byte[] cipherTextByteArr;
            if (cipherText.StartsWith("0x"))
            {
                byte[] temp = new byte[(cipherText.Length - 2) / 2];
                int t = 0;
                int q = 0;
                int tl = temp.Length;
                while (q < tl)
                {
                    temp[q] = Convert.ToByte(cipherText.Substring(t + 2, 2), 16);
                    t += 2;
                    q++;
                }
                int tempLength = temp.Length;
                while (tempLength % 16 != 0)
                {
                    tempLength++;
                }

                cipherTextByteArr = new byte[tempLength];
                Array.Copy(temp, cipherTextByteArr, temp.Length);
                tempLength = temp.Length;
                for (; tempLength < cipherTextByteArr.Length; tempLength++)
                    cipherTextByteArr[tempLength] = Convert.ToByte("00", 16);
                plainText += "0x";
            }
            else
                cipherTextByteArr = new byte[plainText.Length];
            int cipherTextIndex = 0;
            while (true)
            {
                if (cipherTextIndex == cipherTextByteArr.Length)
                    break;
                byte[,] state = new byte[4, 4];
                int o = 0;
                while (o <= 3)
                {
                    int h = 0;
                    while (h <= 3)
                    {
                        state[h, o] = cipherTextByteArr[cipherTextIndex];
                        cipherTextIndex++;
                        h++;
                    }
                    o++;
                }

                byte[,] currentKey = new byte[4, 4];
                int keyRow = 40;
                int keyCol = 0;
                for (int i = 0; i <= 3; i++)
                {
                    for (int j = 0; j <= 3; j++)
                    {
                        currentKey[j, i] = this.Key[keyRow, keyCol];
                        keyCol++;
                    }
                    keyRow++;
                    keyCol = 0;
                }
                keyRow -= 8;
                state = addRoundKey(state, currentKey);
                for (int i = 0; i < 9; i++)
                {
                    state = inverse_Shift_Rows(state);
                    state = inverse_Sub_Bytes(state);

                    for (int q = 0; q <= 3; q++)
                    {
                        for (int m = 0; m <= 3; m++)
                        {
                            currentKey[m, q] = this.Key[keyRow, keyCol];
                            keyCol++;
                        }
                        keyRow++;
                        keyCol = 0;
                    }
                    keyRow -= 8;
                    state = addRoundKey(state, currentKey);
                    state = invMixColumns(state);
                }
                state = inverse_Shift_Rows(state);
                state = inverse_Sub_Bytes(state);
                int u = 0;
                while (u <= 3)
                {
                    int j = 0;
                    while (j <= 3)
                    {
                        currentKey[j, u] = this.Key[keyRow, keyCol];
                        keyCol++;
                        j++;
                    }
                    keyRow++;
                    keyCol = 0;
                    u++;
                }
                state = addRoundKey(state, currentKey);
                byte[] temp = new byte[16];
                int s = 0;
                int iii = 0;
                while (iii <= 3)
                {
                    int j = 0;
                    while (j <= 3)
                    {
                        temp[s] = state[j, iii];
                        s++;
                        j++;
                    }
                    iii++;
                }

                plainText += BitConverter.ToString(temp).Replace("-", string.Empty);
            }

            return plainText;
        }


        //DONE!!!
        public override string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            Key_Schedule(key);
            byte[] plainTextByteArr;

            if (plainText.StartsWith("0x"))
            {
                byte[] temp = new byte[(plainText.Length - 2) / 2];
                int t = 0;

                int i = 0;
                while (i < temp.Length)
                {
                    temp[i] = Convert.ToByte(plainText.Substring(t + 2, 2), 16);
                    t += 2;
                    i++;
                }

                int tempLength = temp.Length;
                while (tempLength % 16 != 0)
                    tempLength++;

                plainTextByteArr = new byte[tempLength];
                Array.Copy(temp, plainTextByteArr, temp.Length);

                int j = temp.Length;
                while (j < plainTextByteArr.Length)
                {
                    plainTextByteArr[j] = Convert.ToByte("00", 16);
                    j++;
                }

                cipherText += "0x";
            }
            else
            {
                plainTextByteArr = new byte[plainText.Length];
            }

            int plainTextIndex = 0;
            while (plainTextIndex < plainTextByteArr.Length)
            {
                byte[,] state = new byte[4, 4];

                int i = 0;
                while (i < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        state[j, i] = plainTextByteArr[plainTextIndex++];
                        j++;
                    }
                    i++;
                }

                byte[,] currentKey = new byte[4, 4];
                int keyRow = 0;
                int keyCol = 0;

                int ii = 0;
                while (ii < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        currentKey[j, ii] = this.Key[keyRow, keyCol++];
                        j++;
                    }
                    keyRow++;
                    keyCol = 0;
                    ii++;
                }

                state = addRoundKey(state, currentKey);

                int round = 0;
                while (round < 9)
                {
                    state = subBytes(state);
                    state = shiftRows(state);
                    state = mix_Columns(state);

                    keyRow = (round + 1) * 4;
                    keyCol = 0;

                    int iii = 0;
                    while (iii < 4)
                    {
                        int j = 0;
                        while (j < 4)
                        {
                            currentKey[j, iii] = this.Key[keyRow, keyCol++];
                            j++;
                        }
                        keyRow++;
                        keyCol = 0;
                        iii++;
                    }

                    state = addRoundKey(state, currentKey);
                    round++;
                }

                state = subBytes(state);
                state = shiftRows(state);

                keyRow = 40;
                keyCol = 0;

                int o = 0;
                while (o < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        currentKey[j, o] = this.Key[keyRow, keyCol++];
                        j++;
                    }
                    keyRow++;
                    keyCol = 0;
                    o++;
                }

                state = addRoundKey(state, currentKey);

                byte[] temp = new byte[16];
                int s = 0;

                int p = 0;
                while (p < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        temp[s++] = state[j, p];
                        j++;
                    }
                    p++;
                }

                cipherText += BitConverter.ToString(temp).Replace("-", string.Empty);
            }

            return cipherText;
        }

        //DONE!!!
        private void Key_Schedule(string key)
        {
            byte[] temp = new byte[16];
            int j = 0;

            int i = 0;
            while (i < 16)
            {
                temp[i] = Convert.ToByte(key.Substring(j + 2, 2), 16);
                j += 2;
                i++;
            }
            j = 0;

            this.Key = new byte[44, 4];
            i = 0;
            while (i < 4)
            {
                int k = 0;
                while (k < 4)
                {
                    this.Key[i, k] = temp[j++];
                    k++;
                }
                i++;
            }

            i = 1;
            while (i < 11)
            {
                int l = 0;
                while (l < 4)
                {
                    byte[] strings = new byte[4];
                    if (l == 0)
                    {
                        byte tmp = this.Key[(4 * i) - 1 + l, 0];
                        strings[0] = this.Key[(4 * i) - 1 + l, 1];
                        strings[1] = this.Key[(4 * i) - 1 + l, 2];
                        strings[2] = this.Key[(4 * i) - 1 + l, 3];
                        strings[3] = tmp;
                        int kk = 0;
                        while (kk < 4)
                        {
                            strings[kk] = SBOXX[strings[kk] >> 4, strings[kk] & 0x0f];
                            kk++;
                        }
                    }
                    else
                    {
                        strings[0] = this.Key[(4 * i) - 1 + l, 0];
                        strings[1] = this.Key[(4 * i) - 1 + l, 1];
                        strings[2] = this.Key[(4 * i) - 1 + l, 2];
                        strings[3] = this.Key[(4 * i) - 1 + l, 3];
                    }
                    int k = 0;
                    while (k < 4)
                    {
                        if (l == 0)
                            strings[k] = Convert.ToByte(this.Key[(4 * i) - 4 + l, k] ^ strings[k] ^ R_con[i - 1, k]);
                        else
                            strings[k] = Convert.ToByte(this.Key[(4 * i) - 4 + l, k] ^ strings[k]);
                        k++;
                    }

                    this.Key[(4 * i) + l, 0] = strings[0];
                    this.Key[(4 * i) + l, 1] = strings[1];
                    this.Key[(4 * i) + l, 2] = strings[2];
                    this.Key[(4 * i) + l, 3] = strings[3];

                    l++;
                }

                i++;
            }
        }

        // DONE! 
        public byte[,] subBytes(byte[,] state)
        {
            int i = 0;
            while (i <= 3)
            {
                int j = 0;
                while (j <= 3)
                {
                    state[i, j] = SBOXX[state[i, j] >> 4, state[i, j] & 0x0f];
                    j++;
                }

                i++;
            }

            return state;
        }

        // DONE!
        static byte[,] shiftRows(byte[,] state)
        {
            byte temp1;
            // first raw   -- no change 

            //Second Row: // shift 1
            temp1 = state[1, 0];
            int i = 0;
            while (i <= 2)
            {
                state[1, i] = state[1, i + 1];
                i++;
            }
            state[1, 3] = temp1;

            //Third Row:  // shift 2
            temp1 = state[2, 0];
            int j = 0;
            while (j <= 2)
            {
                state[2, j] = state[2, j + 1];
                j++;
            }
            state[2, 3] = temp1;


            temp1 = state[2, 0];
            int ii = 0;
            while (ii <= 2)
            {
                state[2, ii] = state[2, ii + 1];
                ii++;

            }
            state[2, 3] = temp1;

            //Forth Row:  // shift 3
            temp1 = state[3, 0];
            int iii = 0;
            while (iii <= 2)
            {
                state[3, iii] = state[3, iii + 1];
                iii++;

            }
            state[3, 3] = temp1;


            temp1 = state[3, 0];
            int b = 0;
            while (b <= 2)
            {
                state[3, b] = state[3, b + 1];
                b++;

            }
            state[3, 3] = temp1;


            temp1 = state[3, 0];
            int bb = 0;
            while (bb <= 2)
            {
                state[3, bb] = state[3, bb + 1];
                bb++;
            }

            state[3, 3] = temp1;

            return state;
        }

        //DONE!
        private byte[,] addRoundKey(byte[,] state2, byte[,] round_Key)
        {
            int i = 0;

            while (i <= 3)
            {
                int j = 0;
                while (j <= 3)
                {
                    state2[i, j] ^= round_Key[i, j];
                    j++;
                }
                i++;
            }

            return state2;
        }


        //DONE!!!
        private byte[,] mix_Columns(byte[,] state)
        {
            int m = 0;
            while (m <= 3)
            {
                byte[] vector = new byte[4];
                int j = 0;
                while (j <= 3)
                {
                    vector[j] = state[j, m];
                    j++;
                }

                byte column0 = (byte)(G_F2(vector[0]) ^ G_F3(vector[1]) ^ vector[2] ^ vector[3]);
                byte column1 = (byte)(vector[0] ^ G_F2(vector[1]) ^ G_F3(vector[2]) ^ vector[3]);
                byte column2 = (byte)(vector[0] ^ vector[1] ^ G_F2(vector[2]) ^ G_F3(vector[3]));
                byte column3 = (byte)(G_F3(vector[0]) ^ vector[1] ^ vector[2] ^ G_F2(vector[3]));

                state[0, m] = column0;
                state[1, m] = column1;
                state[2, m] = column2;
                state[3, m] = column3;

                m++;
            }
            return state;
        }
        //DONE!!!!!!
        private byte G_F2(byte input)
        {
            byte result = (byte)(input << 1); // Multiply by 2 = Shift left by 1

            if ((input & 0x80) != 0) // Check if the MSB of the original input is set
            {
                result ^= 0x1b; // XOR with 0x1b if MSB is set
            }

            return result;
        }

        //DONE!!!!!!
        private byte G_F3(byte input)
        {
            byte input_GF = G_F2(input);
            byte result2 = (byte)(input ^ input_GF); // GF3(input) = XOR between original input and GF2(input)
            return result2;
        }


        //DONE!!!
        private byte[,] inverse_Shift_Rows(byte[,] state)
        {
            byte temp;
            // first Raw -- no change 
            // Second Row: // shift 1
            temp = state[1, 3];
            int i = 3;
            while (i > 0)
            {
                state[1, i] = state[1, i - 1];
                i--;
            }
            state[1, 0] = temp;

            // Third Row: // shift 2
            temp = state[2, 3];
            i = 3;
            while (i > 0)
            {
                state[2, i] = state[2, i - 1];
                i--;
            }
            state[2, 0] = temp;
            temp = state[2, 3];
            i = 3;
            while (i > 0)
            {
                state[2, i] = state[2, i - 1];
                i--;
            }
            state[2, 0] = temp;

            // Fourth Row:  // shift 3
            temp = state[3, 3];
            i = 3;
            while (i > 0)
            {
                state[3, i] = state[3, i - 1];
                i--;
            }
            state[3, 0] = temp;
            temp = state[3, 3];
            i = 3;
            while (i > 0)
            {
                state[3, i] = state[3, i - 1];
                i--;
            }
            state[3, 0] = temp;
            temp = state[3, 3];
            i = 3;
            while (i > 0)
            {
                state[3, i] = state[3, i - 1];
                i--;
            }
            state[3, 0] = temp;

            return state;
        }

        //DONE!!!
        public byte[,] inverse_Sub_Bytes(byte[,] state)
        {
            int i = 0;
            while (i <= 3)
            {
                int j = 0;
                while (j <= 3)
                {
                    state[i, j] = inverse_SBOXX[state[i, j] >> 4, state[i, j] & 0x0f];
                    j++;
                }
                i++;
            }

            return state;
        }


        //DONE!!!
        private byte[,] invMixColumns(byte[,] state)
        {
            int i = 0;
            while (i <= 3)
            {
                byte[] arr = new byte[4];
                int j = 0;
                while (j <= 3)
                {
                    arr[j] = state[j, i];
                    j++;
                }


                byte column0 = (byte)(G_Fe(arr[0]) ^ G_Fb(arr[1]) ^ G_Fd(arr[2]) ^ G_F9(arr[3]));
                byte column1 = (byte)(G_F9(arr[0]) ^ G_Fe(arr[1]) ^ G_Fb(arr[2]) ^ G_Fd(arr[3]));
                byte column2 = (byte)(G_Fd(arr[0]) ^ G_F9(arr[1]) ^ G_Fe(arr[2]) ^ G_Fb(arr[3]));
                byte column3 = (byte)(G_Fb(arr[0]) ^ G_Fd(arr[1]) ^ G_F9(arr[2]) ^ G_Fe(arr[3]));

                state[0, i] = column0;
                state[1, i] = column1;
                state[2, i] = column2;
                state[3, i] = column3;
                i++;
            }

            return state;
        }

        //DONE!!!
        private byte G_F9(byte inp)
        {
            byte g_f = G_F2(inp);
            g_f = G_F2(g_f);
            g_f = G_F2(g_f);
            byte output = (byte)(g_f ^ inp); //X × 9 = (((X × 2) × 2) × 2) + X
            return output;
        }

        //DONE!!!
        private byte G_Fb(byte inp)
        {
            byte g_f = G_F2(inp);
            g_f = G_F2(g_f);
            g_f ^= inp;
            g_f = G_F2(g_f);
            byte output = (byte)(g_f ^ inp); //X × 11 = ((((X × 2) × 2) + X) × 2) + X
            return output;
        }

        //DONE!!!
        private byte G_Fd(byte inp)
        {
            byte g_f = G_F2(inp);
            g_f ^= inp;
            g_f = G_F2(g_f);
            g_f = G_F2(g_f);
            byte output = (byte)(g_f ^ inp); // X × 13 = ((((X × 2) + X) × 2) × 2) + X
            return output;
        }
        //DONE!!!
        private byte G_Fe(byte inp)
        {
            byte g_f = G_F2(inp);
            g_f ^= inp;
            g_f = G_F2(g_f);
            g_f ^= inp;
            g_f = G_F2(g_f);
            byte output = g_f; // X × 14 = ((((X × 2) + X) × 2) + X) × 2
            return output;
        }
    }
}

