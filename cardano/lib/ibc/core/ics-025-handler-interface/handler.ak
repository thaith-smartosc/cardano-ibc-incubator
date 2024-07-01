pub type HandlerState {
  next_client_sequence: Int,
  next_connection_sequence: Int,
  next_channel_sequence: Int,
  bound_port: List<Int>,
}

pub fn new(
  next_client_sequence: Int,
  next_connection_sequence: Int,
  next_channel_sequence: Int,
  bound_port: List<Int>,
) -> HandlerState {
  HandlerState {
    next_client_sequence,
    next_connection_sequence,
    next_channel_sequence,
    bound_port,
  }
}
