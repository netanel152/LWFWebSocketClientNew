package application;


public enum ColorAlertEnum {
    green(0),
    amber(1),
    red(2),
    clear(3);

	private final int value;

	ColorAlertEnum(int val) {
		this.value=val;
	}

	public int getVal(){
		return value;
	}
}