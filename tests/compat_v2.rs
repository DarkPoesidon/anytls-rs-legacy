use anytls::core::{Command, Engine, Frame, PaddingFactory, ProtocolAction, State};

#[test]
fn engine_accepts_v2_settings_and_echoes_serversettings() {
    let state = State::new(PaddingFactory::default());

    // build a Settings frame with v=2 (minimal payload)
    let data = b"v=2".to_vec();
    let frame = Frame::with_data(Command::Settings, 0, bytes::Bytes::copy_from_slice(&data));

    // server-side handling: is_client = false
    let actions = Engine::on_frame(&state, false, &frame).expect("Engine::on_frame failed");

    // peer_version should be recorded as 2
    assert_eq!(state.peer_version(), 2);

    // verify we will send a ServerSettings frame echoing v=2
    let mut found = false;
    for action in actions {
        if let ProtocolAction::SendFrameSync(f) = action
            && f.cmd == Command::ServerSettings
            && f.data.as_ref().windows(3).any(|w| w == b"v=2")
        {
            found = true;
        }
    }

    assert!(found, "Expected ServerSettings with v=2 in actions");
}
