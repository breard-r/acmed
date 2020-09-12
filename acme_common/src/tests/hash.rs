use crate::crypto::HashFunction;

#[test]
fn test_hash_from_str() {
    let test_vectors = vec![
        ("sha256", HashFunction::Sha256),
        ("Sha256", HashFunction::Sha256),
        ("sha-256", HashFunction::Sha256),
        ("SHA_256", HashFunction::Sha256),
        ("sha384", HashFunction::Sha384),
        ("Sha-512", HashFunction::Sha512),
    ];
    for (s, ref_h) in test_vectors {
        let h: HashFunction = s.parse().unwrap();
        assert_eq!(h, ref_h);
    }
}

#[test]
fn test_hash_from_invalid_str() {
    let test_vectors = vec!["sha42", "sha", "", "plop"];
    for s in test_vectors {
        let h = s.parse::<HashFunction>();
        assert!(h.is_err());
    }
}

#[test]
fn test_hash_sha256() {
    let test_vectors = vec![
        (
            "Hello World!".as_bytes(),
            vec![
                127, 131, 177, 101, 127, 241, 252, 83, 185, 45, 193, 129, 72, 161, 214, 93, 252,
                45, 75, 31, 163, 214, 119, 40, 74, 221, 210, 0, 18, 109, 144, 105,
            ],
        ),
        (
            &[],
            vec![
                227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
            ],
        ),
        (
            &[
                194, 43, 6, 43, 252, 50, 206, 26, 240, 105, 85, 119, 40, 153, 213, 123, 158, 59, 8,
                45, 114,
            ],
            vec![
                65, 72, 199, 76, 128, 174, 196, 223, 91, 235, 87, 119, 200, 212, 133, 13, 219, 223,
                60, 4, 73, 70, 65, 41, 226, 83, 221, 107, 112, 29, 205, 28,
            ],
        ),
    ];
    for (data, expected) in test_vectors {
        let h = HashFunction::Sha256;
        let res = h.hash(data);
        assert_eq!(res, expected);
    }
}

#[test]
fn test_hmac_sha256() {
    let test_vectors = vec![
        (
            vec![
                11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
            ],
            vec![72, 105, 32, 84, 104, 101, 114, 101],
            vec![
                176, 52, 76, 97, 216, 219, 56, 83, 92, 168, 175, 206, 175, 11, 241, 43, 136, 29,
                194, 0, 201, 131, 61, 167, 38, 233, 55, 108, 46, 50, 207, 247,
            ],
        ),
        (
            vec![74, 101, 102, 101],
            vec![
                119, 104, 97, 116, 32, 100, 111, 32, 121, 97, 32, 119, 97, 110, 116, 32, 102, 111,
                114, 32, 110, 111, 116, 104, 105, 110, 103, 63,
            ],
            vec![
                91, 220, 193, 70, 191, 96, 117, 78, 106, 4, 36, 38, 8, 149, 117, 199, 90, 0, 63, 8,
                157, 39, 57, 131, 157, 236, 88, 185, 100, 236, 56, 67,
            ],
        ),
        (
            vec![
                170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
                170, 170, 170, 170,
            ],
            vec![
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221,
            ],
            vec![
                119, 62, 169, 30, 54, 128, 14, 70, 133, 77, 184, 235, 208, 145, 129, 167, 41, 89,
                9, 139, 62, 248, 193, 34, 217, 99, 85, 20, 206, 213, 101, 254,
            ],
        ),
        (
            vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25,
            ],
            vec![
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205,
            ],
            vec![
                130, 85, 138, 56, 154, 68, 60, 14, 164, 204, 129, 152, 153, 242, 8, 58, 133, 240,
                250, 163, 229, 120, 248, 7, 122, 46, 63, 244, 103, 41, 102, 91,
            ],
        ),
    ];
    for (key, data, expected) in test_vectors {
        let h = HashFunction::Sha256;
        let res = h.hmac(&key, &data).unwrap();
        assert_eq!(res, expected);
    }
}

#[test]
fn test_hash_sha384() {
    let test_vectors = vec![
        (
            "Hello World!".as_bytes(),
            vec![
                191, 215, 108, 14, 187, 208, 6, 254, 229, 131, 65, 5, 71, 193, 136, 123, 2, 146,
                190, 118, 213, 130, 217, 108, 36, 45, 42, 121, 39, 35, 227, 253, 111, 208, 97, 249,
                213, 207, 209, 59, 143, 150, 19, 88, 230, 173, 186, 74,
            ],
        ),
        (
            &[],
            vec![
                56, 176, 96, 167, 81, 172, 150, 56, 76, 217, 50, 126, 177, 177, 227, 106, 33, 253,
                183, 17, 20, 190, 7, 67, 76, 12, 199, 191, 99, 246, 225, 218, 39, 78, 222, 191,
                231, 111, 101, 251, 213, 26, 210, 241, 72, 152, 185, 91,
            ],
        ),
        (
            &[
                194, 43, 6, 43, 252, 50, 206, 26, 240, 105, 85, 119, 40, 153, 213, 123, 158, 59, 8,
                45, 114,
            ],
            vec![
                170, 126, 84, 2, 141, 91, 106, 70, 80, 53, 98, 101, 184, 3, 34, 146, 130, 238, 146,
                221, 113, 197, 154, 91, 4, 208, 229, 15, 8, 179, 51, 29, 224, 200, 187, 127, 9,
                243, 29, 171, 189, 124, 60, 39, 3, 74, 171, 156,
            ],
        ),
    ];
    for (data, expected) in test_vectors {
        let h = HashFunction::Sha384;
        let res = h.hash(data);
        assert_eq!(res, expected);
    }
}

#[test]
fn test_hmac_sha384() {
    let test_vectors = vec![
        (
            vec![
                11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
            ],
            vec![72, 105, 32, 84, 104, 101, 114, 101],
            vec![
                175, 208, 57, 68, 216, 72, 149, 98, 107, 8, 37, 244, 171, 70, 144, 127, 21, 249,
                218, 219, 228, 16, 30, 198, 130, 170, 3, 76, 124, 235, 197, 156, 250, 234, 158,
                169, 7, 110, 222, 127, 74, 241, 82, 232, 178, 250, 156, 182,
            ],
        ),
        (
            vec![74, 101, 102, 101],
            vec![
                119, 104, 97, 116, 32, 100, 111, 32, 121, 97, 32, 119, 97, 110, 116, 32, 102, 111,
                114, 32, 110, 111, 116, 104, 105, 110, 103, 63,
            ],
            vec![
                175, 69, 210, 227, 118, 72, 64, 49, 97, 127, 120, 210, 181, 138, 107, 27, 156, 126,
                244, 100, 245, 160, 27, 71, 228, 46, 195, 115, 99, 34, 68, 94, 142, 34, 64, 202,
                94, 105, 226, 199, 139, 50, 57, 236, 250, 178, 22, 73,
            ],
        ),
        (
            vec![
                170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
                170, 170, 170, 170,
            ],
            vec![
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221,
            ],
            vec![
                136, 6, 38, 8, 211, 230, 173, 138, 10, 162, 172, 224, 20, 200, 168, 111, 10, 166,
                53, 217, 71, 172, 159, 235, 232, 62, 244, 229, 89, 102, 20, 75, 42, 90, 179, 157,
                193, 56, 20, 185, 78, 58, 182, 225, 1, 163, 79, 39,
            ],
        ),
        (
            vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25,
            ],
            vec![
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205,
            ],
            vec![
                62, 138, 105, 183, 120, 60, 37, 133, 25, 51, 171, 98, 144, 175, 108, 167, 122, 153,
                129, 72, 8, 80, 0, 156, 197, 87, 124, 110, 31, 87, 59, 78, 104, 1, 221, 35, 196,
                167, 214, 121, 204, 248, 163, 134, 198, 116, 207, 251,
            ],
        ),
    ];
    for (key, data, expected) in test_vectors {
        let h = HashFunction::Sha384;
        let res = h.hmac(&key, &data).unwrap();
        assert_eq!(res, expected);
    }
}

#[test]
fn test_hash_sha512() {
    let test_vectors = vec![
        (
            "Hello World!".as_bytes(),
            vec![
                134, 24, 68, 214, 112, 78, 133, 115, 254, 195, 77, 150, 126, 32, 188, 254, 243,
                212, 36, 207, 72, 190, 4, 230, 220, 8, 242, 189, 88, 199, 41, 116, 51, 113, 1, 94,
                173, 137, 28, 195, 207, 28, 157, 52, 180, 146, 100, 181, 16, 117, 27, 31, 249, 229,
                55, 147, 123, 196, 107, 93, 111, 244, 236, 200,
            ],
        ),
        (
            &[],
            vec![
                207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32,
                228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60,
                93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65,
                122, 129, 165, 56, 50, 122, 249, 39, 218, 62,
            ],
        ),
        (
            &[
                194, 43, 6, 43, 252, 50, 206, 26, 240, 105, 85, 119, 40, 153, 213, 123, 158, 59, 8,
                45, 114,
            ],
            vec![
                58, 93, 210, 174, 119, 179, 246, 25, 14, 148, 182, 109, 28, 14, 16, 80, 45, 231,
                104, 169, 130, 43, 39, 221, 12, 112, 85, 159, 123, 6, 227, 35, 61, 24, 158, 190,
                162, 11, 247, 204, 98, 41, 242, 5, 52, 116, 149, 220, 124, 82, 159, 181, 74, 210,
                85, 190, 59, 130, 209, 8, 181, 247, 192, 65,
            ],
        ),
    ];
    for (data, expected) in test_vectors {
        let h = HashFunction::Sha512;
        let res = h.hash(data);
        assert_eq!(res, expected);
    }
}

#[test]
fn test_hmac_sha512() {
    let test_vectors = vec![
        (
            vec![
                11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
            ],
            vec![72, 105, 32, 84, 104, 101, 114, 101],
            vec![
                135, 170, 124, 222, 165, 239, 97, 157, 79, 240, 180, 36, 26, 29, 108, 176, 35, 121,
                244, 226, 206, 78, 194, 120, 122, 208, 179, 5, 69, 225, 124, 222, 218, 168, 51,
                183, 214, 184, 167, 2, 3, 139, 39, 78, 174, 163, 244, 228, 190, 157, 145, 78, 235,
                97, 241, 112, 46, 105, 108, 32, 58, 18, 104, 84,
            ],
        ),
        (
            vec![74, 101, 102, 101],
            vec![
                119, 104, 97, 116, 32, 100, 111, 32, 121, 97, 32, 119, 97, 110, 116, 32, 102, 111,
                114, 32, 110, 111, 116, 104, 105, 110, 103, 63,
            ],
            vec![
                22, 75, 122, 123, 252, 248, 25, 226, 227, 149, 251, 231, 59, 86, 224, 163, 135,
                189, 100, 34, 46, 131, 31, 214, 16, 39, 12, 215, 234, 37, 5, 84, 151, 88, 191, 117,
                192, 90, 153, 74, 109, 3, 79, 101, 248, 240, 230, 253, 202, 234, 177, 163, 77, 74,
                107, 75, 99, 110, 7, 10, 56, 188, 231, 55,
            ],
        ),
        (
            vec![
                170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
                170, 170, 170, 170,
            ],
            vec![
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
                221, 221,
            ],
            vec![
                250, 115, 176, 8, 157, 86, 162, 132, 239, 176, 240, 117, 108, 137, 11, 233, 177,
                181, 219, 221, 142, 232, 26, 54, 85, 248, 62, 51, 178, 39, 157, 57, 191, 62, 132,
                130, 121, 167, 34, 200, 6, 180, 133, 164, 126, 103, 200, 7, 185, 70, 163, 55, 190,
                232, 148, 38, 116, 39, 136, 89, 225, 50, 146, 251,
            ],
        ),
        (
            vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25,
            ],
            vec![
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205,
            ],
            vec![
                176, 186, 70, 86, 55, 69, 140, 105, 144, 229, 168, 197, 246, 29, 74, 247, 229, 118,
                217, 127, 249, 75, 135, 45, 231, 111, 128, 80, 54, 30, 227, 219, 169, 28, 165, 193,
                26, 162, 94, 180, 214, 121, 39, 92, 197, 120, 128, 99, 165, 241, 151, 65, 18, 12,
                79, 45, 226, 173, 235, 235, 16, 162, 152, 221,
            ],
        ),
    ];
    for (key, data, expected) in test_vectors {
        let h = HashFunction::Sha512;
        let res = h.hmac(&key, &data).unwrap();
        assert_eq!(res, expected);
    }
}