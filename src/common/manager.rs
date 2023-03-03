use std::collections::HashMap;
use std::sync::RwLock;

use rocket::serde::json::Json;
use rocket::{post, routes, Ignite, Rocket, State};

use uuid::Uuid;

use crate::common::{Entry, Index, Key, Params, PartySignup};

#[rocket::main]
pub async fn run_manager() -> Result<Rocket<Ignite>, rocket::Error> {
    //     let mut my_config = Config::development();
    //     my_config.set_port(18001);
    let db: HashMap<Key, String> = HashMap::new();
    let db_mtx = RwLock::new(db);
    //rocket::custom(my_config).mount("/", routes![get, set]).manage(db_mtx).launch();

    /////////////////////////////////////////////////////////////////
    //////////////////////////init signups://////////////////////////
    /////////////////////////////////////////////////////////////////

    let keygen_key = "signup-keygen".to_string();
    let sign_key = "signup-sign".to_string();
    let derive_key = "signup-derive".to_string();
    let reshare_key = "signup-reshare".to_string();

    let uuid_keygen = Uuid::new_v4().to_string();
    let uuid_sign = Uuid::new_v4().to_string();
    let uuid_derive = Uuid::new_v4().to_string();
    let uuid_reshare = Uuid::new_v4().to_string();

    let party1 = 0;
    let party_signup_keygen = PartySignup {
        number: party1,
        uuid: uuid_keygen,
    };
    let party_signup_sign = PartySignup {
        number: party1,
        uuid: uuid_sign,
    };
    let party_signup_derive = PartySignup {
        number: party1,
        uuid: uuid_derive,
    };
    let party_signup_reshare = PartySignup {
        number: party1,
        uuid: uuid_reshare,
    };
    {
        let mut hm = db_mtx.write().unwrap();
        hm.insert(
            keygen_key,
            serde_json::to_string(&party_signup_keygen).unwrap(),
        );
        hm.insert(sign_key, serde_json::to_string(&party_signup_sign).unwrap());
        hm.insert(
            derive_key,
            serde_json::to_string(&party_signup_derive).unwrap(),
        );
        hm.insert(
            reshare_key,
            serde_json::to_string(&party_signup_reshare).unwrap(),
        );
    }
    /////////////////////////////////////////////////////////////////
    rocket::build()
        .mount(
            "/",
            routes![
                get,
                set,
                signup_keygen,
                signup_sign,
                signup_derive,
                signup_reshare
            ],
        )
        .manage(db_mtx)
        .launch()
        .await
}

#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: &State<RwLock<HashMap<Key, String>>>,
    request: Json<Index>,
) -> Json<Result<Entry, ()>> {
    let index: Index = request.0;
    let hm = db_mtx.read().unwrap();
    match hm.get(&index.key) {
        Some(v) => {
            let entry = Entry {
                key: index.key,
                value: v.clone().to_string(),
            };
            Json(Ok(entry))
        }
        None => Json(Err(())),
    }
}

#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: &State<RwLock<HashMap<Key, String>>>, request: Json<Entry>) -> Json<Result<(), ()>> {
    let entry: Entry = request.0;
    let mut hm = db_mtx.write().unwrap();
    hm.insert(entry.key.clone(), entry.value.clone());
    Json(Ok(()))
}

#[post("/signupkeygen", format = "json", data = "<request>")]
fn signup_keygen(
    db_mtx: &State<RwLock<HashMap<Key, String>>>,
    request: Json<Params>,
) -> Json<Result<PartySignup, ()>> {
    let parties = request.parties.parse::<u32>().unwrap();
    let key = "signup-keygen".to_string();

    let party_signup = {
        let hm = db_mtx.read().unwrap();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
        if client_signup.number < parties {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };
    let mut hm = db_mtx.write().unwrap();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[post("/signupsign", format = "json", data = "<request>")]
fn signup_sign(
    db_mtx: &State<RwLock<HashMap<Key, String>>>,
    request: Json<Params>,
) -> Json<Result<PartySignup, ()>> {
    let parties = request.parties.parse::<u32>().unwrap();
    let key = "signup-sign".to_string();
    let mut hm = db_mtx.write().unwrap();
    let party_signup = {
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
        if client_signup.number < parties {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[post("/signupderive", format = "json", data = "<request>")]
fn signup_derive(
    db_mtx: &State<RwLock<HashMap<Key, String>>>,
    request: Json<Params>,
) -> Json<Result<PartySignup, ()>> {
    let share_count = request.share_count.parse::<u32>().unwrap();
    let key = "signup-derive".to_string();

    let party_signup = {
        let hm = db_mtx.read().unwrap();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
        if client_signup.number < share_count {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };
    let mut hm = db_mtx.write().unwrap();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[post("/signupreshare", format = "json", data = "<request>")]
fn signup_reshare(
    db_mtx: &State<RwLock<HashMap<Key, String>>>,
    request: Json<Params>,
) -> Json<Result<PartySignup, ()>> {
    let parties = request.parties.parse::<u32>().unwrap();
    let key = "signup-reshare".to_string();

    let party_signup = {
        let hm = db_mtx.read().unwrap();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
        if client_signup.number < parties {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };
    let mut hm = db_mtx.write().unwrap();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}
