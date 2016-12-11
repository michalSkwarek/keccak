#include <iostream>
#include <iomanip>

using namespace std;

class Message {
    char* inputMessage;
    int lengthInputMessage;
protected:
    int bitLength;
    uint64_t* hexMessage;
public:
    Message(const char* = "", int = 0);
    ~Message();
    void calculateLengthInputMessage();
    void paddingLast2Bytes();
    void convertInputMessageToHexMessage();
    uint64_t convertBigEndianLittleEndian(uint64_t = 0);
    void convertHexMessageToLittleEndian();
    void preparationMessage();
};

Message::Message(const char* inputMessage, int bitLength) {
    this->inputMessage = new char[strlen(inputMessage) + 1];
    strcpy(this->inputMessage, inputMessage);
    this->bitLength = bitLength;
    int x = 0;
    ((bitLength + 1) % 576 != 0) ? x = bitLength / 576 + 1 : x = bitLength / 576 + 2;
    hexMessage = new uint64_t[9 * x];
    for(int i = 0; i < 9 * x; ++i) {
        hexMessage[i] = 0x0000000000000000;
    }
}

Message::~Message() {
    delete [] hexMessage;
    delete [] inputMessage;
}

void Message::calculateLengthInputMessage() {
    lengthInputMessage = (int) strlen(inputMessage);
}

void Message::convertInputMessageToHexMessage() {
    int n = lengthInputMessage / 16 + 1;
    char partInputMessage[16];
    for(int i = 0; i < n; ++i) {
        memcpy(partInputMessage, inputMessage + 16 * i, 16);
        hexMessage[i] = strtoull(partInputMessage, NULL, 16);
    }
}

void Message::paddingLast2Bytes() {
    uint64_t tmp = 0x0000000000000001;
    uint64_t tmp2 = 0x00000000000000ff;
    int i = bitLength / 64;
    if(bitLength % 64 == 0) {
        hexMessage[i] = tmp << 56;
    } else if(bitLength % 8 == 0) {
        hexMessage[i] <<= 8;
        hexMessage[i] |= tmp;
        hexMessage[i] <<= 8 * (7 - lengthInputMessage / 2);
    } else if(bitLength % 4 == 0) {
        hexMessage[i] <<= 4;
        hexMessage[i] |= tmp;
        uint64_t lastByte = hexMessage[i] & tmp2;
        lastByte = (lastByte << 4 | lastByte >> (8 - 4));
        lastByte >>= 4;
        lastByte <<= 4;
        hexMessage[i] &= ~tmp2;
        hexMessage[i] |= lastByte & tmp2;
        ++lengthInputMessage;
        hexMessage[i] <<= 8 * (8 - lengthInputMessage / 2);
    } else {
        int j = bitLength % 8;
        hexMessage[i] |= tmp;
        uint64_t lastByte = hexMessage[i] & tmp2;
        lastByte = (lastByte << j | lastByte >> (8 - j));
        hexMessage[i] &= ~tmp2;
        hexMessage[i] |= lastByte & tmp2;
        hexMessage[i] <<= 8 * (8 - lengthInputMessage / 2);
    }
}

uint64_t Message::convertBigEndianLittleEndian(uint64_t x) {
    return (((x & 0xff00000000000000ull) >> 56) |
            ((x & 0x00ff000000000000ull) >> 40) |
            ((x & 0x0000ff0000000000ull) >> 24) |
            ((x & 0x000000ff00000000ull) >>  8) |
            ((x & 0x00000000ff000000ull) <<  8) |
            ((x & 0x0000000000ff0000ull) << 24) |
            ((x & 0x000000000000ff00ull) << 40) |
            ((x & 0x00000000000000ffull) << 56));
}

void Message::convertHexMessageToLittleEndian() {
    for(int i = 0; i < bitLength / 64 + 1; ++i) {
        hexMessage[i] = convertBigEndianLittleEndian(hexMessage[i]);
    }
}

void Message::preparationMessage() {
    calculateLengthInputMessage();
    convertInputMessageToHexMessage();
    paddingLast2Bytes();
    convertHexMessageToLittleEndian();
}

class Keccak : public Message {
    static const uint64_t RC[24];
    uint64_t** state;
    int stepsNumber;
    uint64_t* SHA3HashOutput;
public:
    Keccak(const char* = "", int = 0);
    ~Keccak();
    Keccak& operator=(const Keccak&);
    void calculateStepsNumber();
    void absorbingSponge(int = 0);
    uint64_t ROT(uint64_t, int);
    void theta();
    void rho();
    void pi(Keccak&);
    void chi(Keccak&);
    void iota(int);
    void KeccakFunction(Keccak&);
    void squeezingSponge();
    void printSHA3HashOutput();
};

const uint64_t Keccak::RC[24] = {
        0x0000000000000001ull,
        0x0000000000008082ull,
        0x800000000000808Aull,
        0x8000000080008000ull,
        0x000000000000808Bull,
        0x0000000080000001ull,
        0x8000000080008081ull,
        0x8000000000008009ull,
        0x000000000000008Aull,
        0x0000000000000088ull,
        0x0000000080008009ull,
        0x000000008000000Aull,
        0x000000008000808Bull,
        0x800000000000008Bull,
        0x8000000000008089ull,
        0x8000000000008003ull,
        0x8000000000008002ull,
        0x8000000000000080ull,
        0x000000000000800Aull,
        0x800000008000000Aull,
        0x8000000080008081ull,
        0x8000000000008080ull,
        0x0000000080000001ull,
        0x8000000080008008ull,
};

Keccak::Keccak(const char* inputMessage, int bitLength) : Message(inputMessage, bitLength) {
    SHA3HashOutput = new uint64_t[9];
    state = new uint64_t*[5];
    uint64_t* statePointer = new uint64_t[5 * 5];
    for(int i = 0; i < 5; ++i) {
        state[i] = statePointer + i * 5;
    }
    for(int i = 0; i < 5; ++i) {
        for (int j = 0; j < 5; ++j) {
            state[i][j] = 0x0000000000000000;
        }
    }
}

Keccak::~Keccak() {
    delete [] state[0];
    delete [] state;
    delete [] SHA3HashOutput;
}

Keccak& Keccak::operator=(const Keccak& A) {
    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < 5; ++j) {
            state[i][j] = A.state[i][j];
        }
    }
}

void Keccak::calculateStepsNumber() {
    stepsNumber = bitLength / 576;
    if((bitLength + 1) % 576 == 0) {
        ++stepsNumber;
    }
}

void Keccak::absorbingSponge(int step) {
    int next = 9 * step;
    for(int i = 0; i < 5; ++i)
        for(int j = 0; j < 5; ++j) {
            if(next < 9 * (step + 1)) {
                state[j][i] ^= hexMessage[next++];
            } else {
                state[j][i] ^= 0x0000000000000000;
            }
        }
}

uint64_t Keccak::ROT(uint64_t number, int shift) {
    number = (number << shift) | (number >> (64 - shift));
    return number;
}

void Keccak::theta() {
    uint64_t *C = new uint64_t[5];
    uint64_t *D = new uint64_t[5];
    for(int x = 0; x < 5; ++x) {
        C[x] = state[x][0];
        for(int y = 1; y < 5; ++y) {
            C[x] = C[x] ^ state[x][y];
        }
    }
    for(int x = 0; x < 5; ++x) {
        D[x] = C[(x - 1 + 5) % 5] ^ ROT(C[(x + 1) % 5], 1);
        for(int y = 0; y < 5; ++y) {
            state[x][y] = state[x][y] ^ D[x];
        }
    }
    delete [] D;
    delete [] C;
}

void Keccak::rho() {
    int x = 1, y = 0, pom = 0;
    for(int t = 0; t < 24; ++t) {
        state[x][y] = ROT(state[x][y], (t + 1) * (t + 2) / 2 % 64);
        pom = x;
        x = y;
        y = (2 * pom + 3 * y) % 5;
    }
}

void Keccak::pi(Keccak& k) {
    Keccak k2;
    k2 = k;
    for(int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            state[x][y] = k2.state[(x + 3 * y) % 5][x];
        }
    }
}

void Keccak::chi(Keccak& k) {
    Keccak k2;
    k2 = k;
    for(int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            state[x][y] = k2.state[x][y] ^ (~k2.state[(x + 1) % 5][y] & k2.state[(x + 2) % 5][y]);
        }
    }
}

void Keccak::iota(int i) {
    state[0][0] ^= RC[i];
}

void Keccak::KeccakFunction(Keccak& k) {
    calculateStepsNumber();
    for(int i = 0; i < stepsNumber + 1; ++i) {
        absorbingSponge(i);
        if(i == stepsNumber) {
            state[3][1] ^= 0x8000000000000000ull;
        }
        for(int j = 0; j < 24; ++j) {
            theta();
            rho();
            pi(k);
            chi(k);
            iota(j);
        }
    }
}

void Keccak::squeezingSponge() {
    int next = 0;
    for(int  i = 0; i < 5; ++i)
        for(int  j = 0; j < 5; ++j) {
            SHA3HashOutput[next++] = convertBigEndianLittleEndian(state[j][i]);
            if(next == 9) {
                return;
            }
        }
}

void Keccak::printSHA3HashOutput() {
    for(int i = 0; i < 8; ++i) {
        cout << setw(16) << setfill('0') << hex << SHA3HashOutput[i];
    }
}

int main(int argc, char *argv[]) {
    char* inputMessage = new char[1024];
    cout << "Podaj wiadomosc: ";
    cin >> inputMessage;
    cout << "SHA3 wiadomosci " << inputMessage << " wynosi:" << endl;

    int bitLength = (int) (4 * strlen(inputMessage));

    Keccak k1(inputMessage, bitLength);
    k1.Message::preparationMessage();
    k1.KeccakFunction(k1);
    k1.squeezingSponge();
    k1.printSHA3HashOutput();

    return 0;
}
